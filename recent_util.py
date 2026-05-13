#!/usr/bin/env python3
"""
recent_product.py

Maps CVE IDs to primary product names using the Anthropic API (claude-haiku).

Usage (as a module):
    from recent_util import build_product_map

    products = build_product_map(cves, existing_products)
    products = build_product_map(cves, existing_products, max_entries=2000)

Where `cves` is a list of dicts with at least 'id' and 'description' keys,
and `existing_products` is a dict of previously cached product entries
(typically loaded from the main output file's "products" key).

Each entry in the product map is stored as:
    {"CVE-2024-1234": {"product": "Apache Struts", "added": "2026-03-14T20:47:26.110Z"}}

When `max_entries` is supplied, the oldest entries (by "added" timestamp) are
dropped once the map would exceed that limit.

Requires: ANTHROPIC_API_KEY environment variable.
"""

import json
import os
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from decimal import Decimal
from pathlib import Path
from typing import Iterator, Optional, TypedDict


# ──────────────────────────────────────────────────────────────────────────
# NVD API helpers
# ──────────────────────────────────────────────────────────────────────────

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 2000
NVD_REQUEST_DELAY = 0.7  # NVD recommends > 600ms between requests
NVD_TIMEOUT = 120
NVD_RETRY_BACKOFF = [5, 15, 45]  # seconds; 3 retries on 429/503/timeout

# Each entry is (NVD metrics key, CVSS version label).
CVSS_PRIORITY_DEFAULT = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
)
CVSS_PRIORITY_ANY = CVSS_PRIORITY_DEFAULT + (
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


def nvd_fetch_page(params: dict, start_index: int, api_key: Optional[str]) -> dict:
    """Fetch one page from NVD with retry on 429/503/timeout."""
    query = {**params, "startIndex": start_index, "resultsPerPage": NVD_PAGE_SIZE}
    url = f"{NVD_BASE}?{urllib.parse.urlencode(query)}"
    req = urllib.request.Request(url)
    if api_key:
        req.add_header("apiKey", api_key)

    last_err = None
    for attempt, backoff in enumerate([0, *NVD_RETRY_BACKOFF]):
        if backoff:
            print(f"    retry {attempt} after {backoff}s ({last_err})...", flush=True)
            time.sleep(backoff)
        try:
            with urllib.request.urlopen(req, timeout=NVD_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code in (429, 503):
                continue
            body = e.read().decode("utf-8", errors="replace")
            print(f"  HTTP {e.code} from NVD: {body[:200]}", file=sys.stderr)
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_err = e
            continue
    raise RuntimeError(f"NVD fetch failed after retries: {last_err}")


def nvd_paginate(params: dict, api_key: Optional[str]) -> Iterator[dict]:
    """Yield raw NVD vulnerability items across all pages for the given query."""
    start_index = 0
    total = None
    while True:
        if start_index > 0:
            time.sleep(NVD_REQUEST_DELAY)
        page_num = start_index // NVD_PAGE_SIZE + 1
        data = nvd_fetch_page(params, start_index, api_key)
        if total is None:
            total = data.get("totalResults", 0)
            print(f"  total: {total}", flush=True)
        items = data.get("vulnerabilities", [])
        print(f"  page {page_num}: got {len(items)}", flush=True)
        for item in items:
            yield item
        start_index += NVD_PAGE_SIZE
        if total == 0 or start_index >= total:
            break


def extract_cvss(metrics: Optional[dict], priority=CVSS_PRIORITY_DEFAULT) -> Optional[dict]:
    """Pick the best CVSS metric block per priority list. Prefers Primary entries.
    Returns {version, vectorString, baseScore} or None if nothing scored.
    """
    if not metrics:
        return None
    for key, label in priority:
        entries = metrics.get(key, [])
        chosen = next(
            (m for m in entries if m.get("type") == "Primary"),
            entries[0] if entries else None,
        )
        if not chosen:
            continue
        data = chosen.get("cvssData", {})
        vector = data.get("vectorString")
        score = data.get("baseScore")
        if vector and score is not None:
            return {"version": label, "vectorString": vector, "baseScore": score}
    return None


def transform_cve(item: dict, priority=CVSS_PRIORITY_DEFAULT) -> Optional[dict]:
    """Transform a raw NVD vulnerability item into the standard CveEntry shape.
    Returns None when no CVSS vector matching the priority list is present.
    """
    cve = item.get("cve", {})
    cvss = extract_cvss(cve.get("metrics", {}), priority)
    if not cvss:
        return None
    descriptions = cve.get("descriptions", [])
    en_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "description": en_desc,
        "cvss": cvss,
    }


# ──────────────────────────────────────────────────────────────────────────
# DynamoDB item shape
# ──────────────────────────────────────────────────────────────────────────


def cve_to_ddb_item(rec: dict, product: str) -> dict:
    """Flatten a CveEntry plus a product name into the row stored in DynamoDB.
    baseScore is converted to Decimal so boto3 will accept it.
    """
    cvss = rec["cvss"]
    return {
        "id": rec["id"],
        "published": rec.get("published") or "",
        "lastModified": rec.get("lastModified") or "",
        "description": rec.get("description") or "",
        "version": cvss["version"],
        "vectorString": cvss["vectorString"],
        "baseScore": Decimal(str(cvss["baseScore"])),
        "product": product,
    }


# ──────────────────────────────────────────────────────────────────────────
# Product-map and JSONL writer (Anthropic-backed)
# ──────────────────────────────────────────────────────────────────────────


class CveEntryCVSS(TypedDict, total=True):
    version: str
    vectorString: str
    baseScore: float


class CveEntry(TypedDict, total=False):
    id: str
    published: str
    lastModified: str
    description: str
    cvss: CveEntryCVSS


# class CveFlat(TypedDict, total=False):
#     id: str
#     published: str
#     lastModified: str
#     description: str
#     version: str
#     vectorString: str
#     baseScore: float

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-haiku-4-5"
ANTHROPIC_VERSION = "2023-06-01"
BATCH_SIZE = 20

# Sentinel used for entries migrated from the old flat-string format so they
# sort as the very oldest and are evicted first when max_entries is applied.
EPOCH = "1970-01-01T00:00:00+00:00"

SYSTEM_PROMPT = """You are a CVE analyst. For each CVE provided, extract the primary software product or tool that the vulnerability affects. The best name is often found in the first sentence of the description. Favor returning 1 to 2 words representing the most commonly recognized name for the product. If the name is not obvious or multiple products are referenced, select the most commonly recognized vendor or company name. Retain the ordering of the words in the name as presented in the description.

Examples:
- "Apache httpd 2.4.x" → "Apache httpd"
- "Microsoft Windows Win32k" → "Windows"
- "OpenSSL libssl" → "OpenSSL"
- "A vulnerability was identified in D-Link DNS-120, DNR-202L, DNS-315L, DNS-320" → "D-Link"
- "A vulnerability was identified in bazinga012 mcp_code_executor up to 0.3.0." → "mcp_code_executor"
- "A security flaw has been discovered in Tecnick TCExam up to 16.6.0." → "Tecnick TCExam"
- "An authenticated user with the read role may read limited amounts of uninitialized stack memory via specially-crafted issuances of the filemd5 command." → "filemd5"
- "YAML::Syck versions through 1.36 for Perl has several potential security vulnerabilities including a high-severity heap buffer overflow in the YAML emitter." → "YAML::Syck"
- "GCB/FCB Audit Software developed by DrangSoft has a Missing Authentication vulnerability" → "GCB/FCB Audit Software"
- "NULL Pointer Dereference vulnerability in Softing Industrial Automation GmbH smartLink SW-HT (Webserver modules)" → "smartLink SW-HT"
- "An Incorrect Access Control vulnerability exists in INDEX-EDUCATION PRONOTE prior to 2025.2.8." → "INDEX-EDUCATION PRONOTE"

If the CVE description does not clearly identify a specific product, tool, vendor, or company name (e.g., it describes a generic protocol issue or a vulnerability in an unnamed library), return "Unknown".

Respond with JSON only. No preamble, no markdown fences:
[{ "id": "CVE-2026-XXXXX", "product": "Product Name" }, ...]
"""


def normalize_products(data: dict) -> dict:
    """Normalize a product map, handling both current and legacy formats.

    Supports the current format (values are ``{"product": ..., "added": ...}``)
    and the legacy flat format (values are plain strings or ``null``).  Legacy
    entries are promoted to the new format with ``added`` set to the epoch so
    they are evicted first when ``max_entries`` is applied.
    """
    result = {}
    for cve_id, val in data.items():
        if isinstance(val, dict) and "product" in val:
            result[cve_id] = val
        else:
            result[cve_id] = {"product": val, "added": EPOCH}
    return result


def call_anthropic(batch: list, api_key: str) -> dict:
    """Call the Anthropic Messages API for a batch of CVEs.

    `batch` is a list of dicts with 'id' and 'description'.
    Returns a dict mapping CVE ID → product name (str or None).
    """
    user_lines = "\n".join(f"{item['id']}: {item['description']}" for item in batch)
    user_content = "Map these CVEs to their primary product names:\n\n" + user_lines

    payload = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": 1024,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user_content}],
    }

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        ANTHROPIC_API_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        print(f"  Anthropic HTTP {e.code}: {err_body[:200]}", file=sys.stderr)
        raise
    except urllib.error.URLError as e:
        print(f"  Anthropic network error: {e.reason}", file=sys.stderr)
        raise

    # Extract text content from the response
    text = ""
    for block in result.get("content", []):
        if block.get("type") == "text":
            text = block["text"]
            break

    if not text:
        print("  Warning: empty response from Anthropic", file=sys.stderr)
        return {}

    # Strip markdown code fences if present
    stripped = text.strip()
    if stripped.startswith("```"):
        # Remove opening fence (```json or ```)
        stripped = stripped.split("\n", 1)[-1] if "\n" in stripped else ""
        if stripped.endswith("```"):
            stripped = stripped[:-3].strip()
        text = stripped

    def to_dict(obj: object) -> dict:
        """Convert parsed JSON to a CVE-ID → product dict."""
        if isinstance(obj, dict):
            return obj
        if isinstance(obj, list):
            return {
                item["id"]: item["product"]
                for item in obj
                if isinstance(item, dict) and "id" in item and "product" in item
            }
        return {}

    # Parse the JSON mapping returned by the model
    try:
        result = to_dict(json.loads(text))
        if result:
            return result
    except json.JSONDecodeError:
        pass

    # Fallback: locate a JSON array or object within the response text
    for open_ch, close_ch in [("[", "]"), ("{", "}")]:
        start = text.find(open_ch)
        end = text.rfind(close_ch) + 1
        if start >= 0 and end > start:
            try:
                result = to_dict(json.loads(text[start:end]))
                if result:
                    return result
            except json.JSONDecodeError:
                pass

    print(
        f"  Warning: could not parse product mapping from response: {text[:200]}",
        file=sys.stderr,
    )
    return {}


def build_product_map(
    cves: list[CveEntry],
    existing_products: dict,
    max_entries: Optional[int] = None,
) -> dict:
    """Build a CVE-to-product map, returning the dict directly.

    - Uses *existing_products* as a cache of previously resolved entries.
    - Calls the Anthropic API only for CVEs not already cached.
    - If *max_entries* is set, drops the oldest entries (by ``added``
      timestamp) so the map never exceeds that count.

    Returns the product map dict (possibly unchanged if the API key is
    missing or all CVEs are already cached).
    """
    existing = normalize_products(existing_products)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(
            "  ANTHROPIC_API_KEY not set: skipping product map.",
            file=sys.stderr,
        )
        return existing

    new_cves = [c for c in cves if c["id"] not in existing]
    print(f"Product map: {len(existing)} cached, {len(new_cves)} new CVEs to look up")

    total_batches = (len(new_cves) + BATCH_SIZE - 1) // BATCH_SIZE if new_cves else 0

    for i in range(0, len(new_cves), BATCH_SIZE):
        batch = new_cves[i : i + BATCH_SIZE]
        batch_num = i // BATCH_SIZE + 1
        print(
            f"  Batch {batch_num}/{total_batches}: querying {len(batch)} CVEs...",
            end=" ",
            flush=True,
        )
        for attempt in range(4):
            try:
                mapping = call_anthropic(batch, api_key)
                pub_by_id = {c["id"]: c.get("published", "") for c in batch}
                for cve_id, product_name in mapping.items():
                    existing[cve_id] = {
                        "product": product_name,
                        "added": pub_by_id.get(cve_id, ""),
                    }
                unknown = sum(
                    1 for v in mapping.values() if v.strip().lower() == "unknown"
                )
                print(
                    f"got {len(mapping)} products ({len(mapping) - unknown} named, {unknown} unknown)"
                )
                break
            except Exception as exc:
                if attempt < 3 and "overloaded" in str(exc).lower():
                    wait = 10 * (attempt + 1)
                    print(f"overloaded, retrying in {wait}s...", flush=True)
                    time.sleep(wait)
                else:
                    print(f"failed ({exc})", file=sys.stderr)
                    break

    # Trim to max_entries, keeping the newest by "added" timestamp
    if max_entries is not None and len(existing) > max_entries:
        sorted_items = sorted(
            existing.items(),
            key=lambda kv: kv[1]["added"],
            reverse=True,
        )
        existing = dict(sorted_items[:max_entries])
        print(f"  Trimmed product map to {max_entries} newest entries")

    return existing


def write_jsonl(
    cves: list[CveEntry], products: dict[str, dict[str, str]], raw_path: Path
) -> Path:
    """Build a flattened representation of all data."""
    cve_to_product = {k: v["product"] for k, v in products.items()}
    out_path = raw_path.with_suffix(".jsonl")
    with open(out_path, "w", encoding="utf-8") as f:
        for entry in cves:
            d = dict()
            for key in ("id", "published", "lastModified", "description"):
                d[key] = entry.get(key, "")

            cvss = entry["cvss"]
            for key in ("version", "vectorString", "baseScore"):
                d[key] = cvss[key]

            d["product"] = cve_to_product.get(d["id"], "Unknown")

            f.write(json.dumps(d) + "\n")
    return out_path
