#!/usr/bin/env python3
"""
cve_product.py

Maps CVE IDs to primary product names using the Anthropic API (claude-haiku).

Usage (as a module):
    from cve_product import write_product_map

    write_product_map(cves, output_path)

Where `cves` is a list of dicts with at least 'id' and 'description' keys,
and `output_path` is a pathlib.Path to the main JSON output file.

The product map is written to a sibling file with '-product' inserted before
the '.json' suffix (e.g. 'data/kev-recent.json' → 'data/kev-recent-product.json').

Requires: ANTHROPIC_API_KEY environment variable.
"""

import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional


ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-haiku-4-5"
ANTHROPIC_VERSION = "2023-06-01"
BATCH_SIZE = 20

SYSTEM_PROMPT = (
    "You are a cybersecurity expert. For each CVE description provided, "
    "identify the single primary product affected (vendor and product name, "
    "e.g. 'Apache Log4j', 'Microsoft Windows', 'Cisco IOS XE'). "
    "Respond with a JSON object mapping each CVE ID to its primary product "
    "name as a string. Use null if the product cannot be determined. "
    "Respond with only the JSON object and nothing else."
)


def _product_path(output_path: Path) -> Path:
    """Derive the product-map file path from the main output path.

    Example: 'data/kev-recent.json' → 'data/kev-recent-product.json'
    """
    return output_path.with_name(output_path.stem + "-product.json")


def _load_existing(product_path: Path) -> dict:
    """Load an existing CVE→product mapping from disk, or return empty dict."""
    if product_path.exists():
        try:
            with open(product_path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, OSError) as exc:
            print(
                f"  Warning: could not read {product_path}: {exc}",
                file=sys.stderr,
            )
    return {}


def _call_anthropic(batch: list, api_key: str) -> dict:
    """Call the Anthropic Messages API for a batch of CVEs.

    `batch` is a list of dicts with 'id' and 'description'.
    Returns a dict mapping CVE ID → product name (str or None).
    """
    user_lines = "\n".join(
        f"{item['id']}: {item['description']}" for item in batch
    )
    user_content = (
        "Map these CVEs to their primary product names:\n\n" + user_lines
    )

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

    # Parse the JSON mapping returned by the model
    try:
        mapping = json.loads(text)
        if isinstance(mapping, dict):
            return mapping
    except json.JSONDecodeError:
        pass

    # Fallback: locate a JSON object within the response text
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            mapping = json.loads(text[start:end])
            if isinstance(mapping, dict):
                return mapping
        except json.JSONDecodeError:
            pass

    print(
        f"  Warning: could not parse product mapping from response: {text[:200]}",
        file=sys.stderr,
    )
    return {}


def write_product_map(cves: list, output_path: Path) -> Optional[Path]:
    """Build and write a CVE-to-product map alongside *output_path*.

    - Loads any existing mapping from the ``<stem>-product.json`` file.
    - Calls the Anthropic API only for CVEs not already in the cache.
    - Writes the updated mapping back to disk.

    Returns the Path of the product-map file, or None when
    ``ANTHROPIC_API_KEY`` is not set.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(
            "  ANTHROPIC_API_KEY not set — skipping product map.",
            file=sys.stderr,
        )
        return None

    product_path = _product_path(Path(output_path))
    existing = _load_existing(product_path)

    new_cves = [c for c in cves if c["id"] not in existing]
    print(
        f"Product map: {len(existing)} cached, {len(new_cves)} new CVEs to look up"
    )

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
            mapping = _call_anthropic(batch, api_key)
            existing.update(mapping)
            print(f"got {len(mapping)} products")
        except Exception as exc:
            print(f"failed ({exc})", file=sys.stderr)
            # Continue with next batch; unresolved CVEs remain absent from map

    with open(product_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)

    print(f"Product map written to: {product_path}")
    return product_path
