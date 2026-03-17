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
import urllib.request
import urllib.error
from typing import Optional, TypedDict


class CveEntry(TypedDict, total=False):
    id: str
    description: str
    published: str


ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-haiku-4-5"
ANTHROPIC_VERSION = "2023-06-01"
BATCH_SIZE = 20

# Sentinel used for entries migrated from the old flat-string format so they
# sort as the very oldest and are evicted first when max_entries is applied.
EPOCH = "1970-01-01T00:00:00+00:00"

SYSTEM_PROMPT = """You are a CVE analyst. For each CVE provided, extract the primary software product or tool that the vulnerability affects. Return exactly 1 to 2 words representing the most commonly recognized name for that product.

Normalize variations to a single canonical name. For example:
- "Apache HTTP Server", "httpd", "Apache httpd 2.4.x" → "Apache httpd"
- "Google Chromium", "Chrome browser" → "Chrome"
- "Microsoft Windows Win32k" → "Windows"
- "OpenSSL libssl" → "OpenSSL"

If the CVE description does not clearly identify a specific product (e.g., it describes a generic protocol issue or a vulnerability in an unnamed library), return "Unknown".

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
            "  ANTHROPIC_API_KEY not set — skipping product map.",
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
        try:
            mapping = call_anthropic(batch, api_key)
            pub_by_id = {c["id"]: c.get("published", "") for c in batch}
            for cve_id, product_name in mapping.items():
                existing[cve_id] = {
                    "product": product_name,
                    "added": pub_by_id.get(cve_id, ""),
                }
            print(f"got {len(mapping)} products")
        except Exception as exc:
            print(f"failed ({exc})", file=sys.stderr)

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
