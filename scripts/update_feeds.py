#!/usr/bin/env python3
"""Refresh bundled threat feeds (Spamhaus DROP). Run manually, at most once per day."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
DROP_CACHE = ROOT / "data" / "feeds" / "drop_cache.json"
DROP_URL = "https://www.spamhaus.org/drop/drop_v4.json"


def update_drop() -> int:
    print(f"[*] Fetching {DROP_URL}")
    resp = requests.get(DROP_URL, timeout=30)
    resp.raise_for_status()
    entries = resp.json()
    cidrs = [
        e["cidr"]
        for e in entries
        if isinstance(e, dict) and "cidr" in e and e.get("type") is None
    ]
    DROP_CACHE.parent.mkdir(parents=True, exist_ok=True)
    DROP_CACHE.write_text(
        json.dumps({
            "fetched_at": time.time(),
            "cidrs": cidrs,
            "source": DROP_URL,
        }, indent=2),
        encoding="utf-8",
    )
    print(f"[+] Saved {len(cidrs)} DROP CIDRs to {DROP_CACHE}")
    return len(cidrs)


def main() -> int:
    try:
        update_drop()
        return 0
    except requests.RequestException as exc:
        print(f"[!] Feed update failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
