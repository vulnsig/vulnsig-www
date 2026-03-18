#!/usr/bin/env python3
"""
recent-kev.py

Fetches CISA Known Exploited Vulnerabilities (KEV) within a date window,
enriches each entry with CVSS data from the MITRE CVE API, and writes the
results to a JSON file.

Usage:
    python recent-kev.py
    python recent-kev.py --days 90
    python recent-kev.py --start 2025-01-01 --end 2025-03-31
    python recent-kev.py --output ./data --filename kev-recent.json
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import date, timedelta, datetime, timezone
from pathlib import Path

from recent_util import build_product_map


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MITRE_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
REQUEST_DELAY = 0.1  # seconds between MITRE API requests

# Highest version wins
CVSS_PRIORITY = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
CVSS_VERSION_LABEL = {
    "cvssV4_0": "4.0",
    "cvssV3_1": "3.1",
    "cvssV3_0": "3.0",
    "cvssV2_0": "2.0",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Fetch recent KEV entries enriched with CVSS data."
    )
    parser.add_argument(
        "--days",
        type=float,
        default=180.0,
        help="How many days back to collect KEV entries (default: 180)",
    )
    parser.add_argument(
        "--start",
        type=str,
        default=None,
        help="Window start date (YYYY-MM-DD). Overrides --days.",
    )
    parser.add_argument(
        "--end",
        type=str,
        default=None,
        help="Window end date (YYYY-MM-DD). Defaults to today.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data",
        help="Output directory (default: ./data)",
    )
    parser.add_argument(
        "--filename",
        type=str,
        default="kev-recent.json",
        help="Output filename (default: kev-recent.json)",
    )
    return parser.parse_args()


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "recent-kev/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"  HTTP {e.code}: {body[:200]}", file=sys.stderr)
        raise
    except urllib.error.URLError as e:
        print(f"  Network error: {e.reason}", file=sys.stderr)
        raise


def extract_cvss(containers):
    """
    Search CNA and all ADP containers for the highest-priority CVSS entry.
    Returns dict with version, vectorString, baseScore, or None.
    """
    metric_entries = []

    cna = containers.get("cna", {})
    metric_entries.extend(cna.get("metrics", []))

    for adp in containers.get("adp", []):
        metric_entries.extend(adp.get("metrics", []))

    for key in CVSS_PRIORITY:
        for entry in metric_entries:
            cvss = entry.get(key)
            if cvss and cvss.get("vectorString"):
                return {
                    "version": CVSS_VERSION_LABEL[key],
                    "vectorString": cvss["vectorString"],
                    "baseScore": cvss.get("baseScore"),
                }

    return None


def main():
    args = parse_args()

    today = date.today()
    window_end = date.fromisoformat(args.end) if args.end else today
    window_start = (
        date.fromisoformat(args.start)
        if args.start
        else window_end - timedelta(days=args.days)
    )

    print(f"Date window: {window_start} → {window_end}")

    # Fetch and filter KEV catalog
    print("Fetching KEV catalog from CISA...", end=" ", flush=True)
    kev = fetch_json(KEV_URL)
    all_vulns = kev.get("vulnerabilities", [])
    print(f"got {len(all_vulns)} total entries")

    in_window = [
        {
            "cveID": v["cveID"],
            "vulnerabilityName": v["vulnerabilityName"],
            "dateAdded": v["dateAdded"],
        }
        for v in all_vulns
        if window_start <= date.fromisoformat(v["dateAdded"]) <= window_end
    ]
    in_window.sort(key=lambda v: v["dateAdded"], reverse=True)

    print(f"Found {len(in_window)} KEV entries in window")
    if not in_window:
        print(
            "No entries in date window. Try widening the range with --days.",
            file=sys.stderr,
        )

    # Enrich each entry with CVSS from MITRE
    print(f"\nFetching CVSS data from MITRE CVE API...")
    cves = []
    skipped = 0

    for i, vuln in enumerate(in_window):
        cve_id = vuln["cveID"]
        print(f"  [{i + 1}/{len(in_window)}] {cve_id}...", end=" ", flush=True)
        if i > 0:
            time.sleep(REQUEST_DELAY)
        try:
            data = fetch_json(MITRE_URL.format(cve_id=cve_id))
            cvss = extract_cvss(data.get("containers", {}))
        except Exception:
            cvss = None

        if not cvss:
            print("no CVSS: skipped")
            skipped += 1
            continue

        print(f"CVSS {cvss['version']} score={cvss['baseScore']}")
        cves.append(
            {
                "id": cve_id,
                "published": vuln["dateAdded"],
                "description": vuln["vulnerabilityName"],
                "cvss": cvss,
            }
        )

    print(
        f"\nResults: {len(in_window)} entries, "
        f"{skipped} skipped (no CVSS), "
        f"{len(cves)} kept"
    )

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / args.filename

    # Load existing products from current output file (if any)
    existing_products = {}
    if out_path.exists():
        try:
            with open(out_path, encoding="utf-8") as f:
                existing_products = json.load(f).get("products", {})
        except (json.JSONDecodeError, OSError):
            pass

    products = build_product_map(cves, existing_products, 1000)

    payload = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "windowStart": window_start.isoformat(),
        "windowEnd": window_end.isoformat(),
        "cves": cves,
        "products": products,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"Written to: {out_path}")


if __name__ == "__main__":
    main()
