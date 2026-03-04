#!/usr/bin/env python3
"""
fetch_cves.py

Downloads CVEs published in the last 24 hours from the NVD API v2,
filters out any without a CVSS v3.1 or v4.0 vector, and writes the
results to a local JSON file.

Usage:
    python fetch_cves.py
    python fetch_cves.py --output /path/to/dir
    python fetch_cves.py --hours 12 --output ./out
    python fetch_cves.py --api-key YOUR_KEY

Environment variable alternative to --api-key:
    NVD_API_KEY=YOUR_KEY python fetch_cves.py
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
REQUEST_DELAY = 0.7  # NVD recommends > 600ms between requests


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch recent scored CVEs from NVD.")
    parser.add_argument(
        "--hours",
        type=float,
        default=24.0,
        help="How many hours back to search (default: 24)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data",
        help="Output directory (default: ./data)",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="NVD API key (or set NVD_API_KEY env var). Optional but recommended.",
    )
    parser.add_argument(
        "--filename",
        type=str,
        default="cve-recent.json",
        help="Output filename (default: cve-recent.json)",
    )
    return parser.parse_args()


def build_window(hours):
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    # NVD expects format: 2026-03-01T00:00:00.000
    fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000")
    return fmt(start), fmt(end)


def fetch_page(params, start_index, api_key):
    query = {**params, "startIndex": start_index, "resultsPerPage": PAGE_SIZE}
    url = f"{NVD_BASE}?{urllib.parse.urlencode(query)}"

    req = urllib.request.Request(url)
    if api_key:
        req.add_header("apiKey", api_key)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"  HTTP {e.code} from NVD: {body[:200]}", file=sys.stderr)
        raise
    except urllib.error.URLError as e:
        print(f"  Network error: {e.reason}", file=sys.stderr)
        raise


def extract_cvss(metrics):
    """
    Return the best available CVSS data from a CVE metrics block.
    Preference: v4.0 → v3.1. Returns None if neither is present.
    """
    if not metrics:
        return None

    # CVSS v4.0
    for entry in metrics.get("cvssMetricV40", []):
        data = entry.get("cvssData", {})
        if data.get("vectorString"):
            return {
                "version": "4.0",
                "vectorString": data["vectorString"],
                "baseScore": data.get("baseScore"),
                # "baseSeverity": data.get("baseSeverity"),
                # "source": entry.get("source"),
            }

    # CVSS v3.1 — prefer "Primary" source (NVD) over CNA
    v31_entries = metrics.get("cvssMetricV31", [])
    v31 = next(
        (m for m in v31_entries if m.get("type") == "Primary"),
        v31_entries[0] if v31_entries else None,
    )
    if v31:
        data = v31.get("cvssData", {})
        if data.get("vectorString"):
            return {
                "version": "3.1",
                "vectorString": data["vectorString"],
                "baseScore": data.get("baseScore"),
                # "baseSeverity": data.get("baseSeverity"),
                # "source": v31.get("source"),
            }

    return None


def transform(item):
    """
    Transform a raw NVD vulnerability item into a compact dict.
    Returns None if no CVSS vector is present.
    """
    cve = item.get("cve", {})
    cvss = extract_cvss(cve.get("metrics", {}))
    if not cvss:
        return None

    descriptions = cve.get("descriptions", [])
    en_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    # weaknesses = [
    #     d["value"]
    #     for w in cve.get("weaknesses", [])
    #     for d in w.get("description", [])
    # ]

    # references = [r["url"] for r in cve.get("references", [])[:3]]

    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "description": en_desc,
        "cvss": cvss,
        # "weaknesses": weaknesses,
        # "references": references,
    }


def main():
    args = parse_args()
    api_key = args.api_key or os.environ.get("NVD_API_KEY")

    # if not api_key:
    #     print(
    #         "Warning: no API key provided. Rate limit is 5 req/30s. "
    #         "Use --api-key or set NVD_API_KEY env var.",
    #         file=sys.stderr,
    #     )

    window_start, window_end = build_window(args.hours)
    print(f"Fetching CVEs published between {window_start} and {window_end} UTC")

    params = {"pubStartDate": window_start, "pubEndDate": window_end}
    start_index = 0
    total_results = None
    raw_items = []

    # Paginate
    while True:
        page_num = start_index // PAGE_SIZE + 1
        print(f"  Fetching page {page_num} (startIndex={start_index})...", end=" ")

        if start_index > 0:
            time.sleep(REQUEST_DELAY)

        data = fetch_page(params, start_index, api_key)

        if total_results is None:
            total_results = data.get("totalResults", 0)
            print(f"  Total CVEs in window: {total_results}")

        batch = data.get("vulnerabilities", [])
        raw_items.extend(batch)
        print(f"got {len(batch)}")

        start_index += PAGE_SIZE
        if start_index >= total_results:
            break

    # Transform and filter
    cves = [t for item in raw_items if (t := transform(item)) is not None]
    filtered_out = len(raw_items) - len(cves)

    print(
        f"\nResults: {len(raw_items)} total CVEs, "
        f"{filtered_out} removed (no vector), "
        f"{len(cves)} kept"
    )

    # Sort newest first
    cves.sort(key=lambda c: c["published"], reverse=True)

    payload = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "windowStart": window_start,
        "windowEnd": window_end,
        "cves": cves,
    }

    # Write output
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / args.filename

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"Written to: {out_path}")


if __name__ == "__main__":
    main()