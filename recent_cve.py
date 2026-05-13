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
from datetime import datetime, timezone, timedelta
from pathlib import Path

from recent_util import build_product_map, nvd_paginate, transform_cve, write_jsonl


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch recent scored CVEs from NVD.")
    parser.add_argument(
        "--hours",
        type=float,
        default=72.0,
        help="How many hours back to search (default: 48)",
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


def main():
    args = parse_args()
    api_key = args.api_key or os.environ.get("NVD_API_KEY")
    window_start, window_end = build_window(args.hours)
    print(f"Fetching CVEs published between {window_start} and {window_end} UTC")

    params = {"pubStartDate": window_start, "pubEndDate": window_end}
    raw_count = 0
    cves = []
    for item in nvd_paginate(params, api_key):
        raw_count += 1
        rec = transform_cve(item)
        if rec is not None:
            cves.append(rec)

    print(
        f"\nResults: {raw_count} total CVEs, "
        f"{raw_count - len(cves)} removed (no v3.1/v4.0 vector), "
        f"{len(cves)} kept"
    )

    # Sort newest first
    cves.sort(key=lambda c: c["published"], reverse=True)

    # Write output
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
        "windowStart": window_start,
        "windowEnd": window_end,
        "cves": cves,
        "products": products,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"Written to: {out_path}")

    out_path_jsonl = write_jsonl(cves, products, out_path)
    print(f"Written to: {out_path_jsonl}")


if __name__ == "__main__":
    main()
