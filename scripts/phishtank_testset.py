#!/usr/bin/env python3
"""Fetch PhishTank's verified-phishing dataset and benchmark intel/phishing.py
against it.

This script downloads a list of *strings* (URLs that PhishTank's community
has verified as phishing) — it never connects to any of those URLs itself.
Everything downstream is pure local string analysis via intel.phishing,
the same module wired into the live scan pipeline.

Setup:
    1. Register for a free key at https://www.phishtank.com/developer_info.php
    2. Put it in your .env file (never commit this):
           PHISHTANK_API_KEY=your_key_here
    3. Run:
           python scripts/fetch_phishtank_testset.py

Without a key the script still works against the public unauthenticated
feed, but PhishTank rate-limits that endpoint hard (several users report
429/509 errors within a handful of requests) — a free key removes that
ceiling and is worth getting before you run this more than once.

Output:
    - data/phishtank/online-valid.csv   (cached raw dataset)
    - A hit-rate report printed to stdout: how many PhishTank-verified
      phishing URLs your local heuristics actually flag, broken down by
      which rule fired most often, plus a few example misses so you can
      see what your heuristics don't catch yet.
"""

from __future__ import annotations

import csv
import io
import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / "data" / "phishtank"
CACHE_PATH = CACHE_DIR / "online-valid.csv"

UNAUTH_URL = "http://data.phishtank.com/data/online-valid.csv"
AUTH_URL_TMPL = "http://data.phishtank.com/data/{key}/online-valid.csv"

# Make sure intel/ is importable when run as `python scripts/this_file.py`
sys.path.insert(0, str(ROOT))

from intel import phishing  # noqa: E402


def fetch_dataset(api_key: str | None, force: bool = False) -> Path:
    """Download (or reuse cached) PhishTank verified-phishing CSV.

    Returns the local path. Raises RuntimeError with a clear message on
    rate-limit (429/509) or other HTTP failure rather than crashing with
    a raw traceback.
    """
    if CACHE_PATH.exists() and not force:
        print(f"[*] using cached dataset: {CACHE_PATH}")
        return CACHE_PATH

    url = AUTH_URL_TMPL.format(key=api_key) if api_key else UNAUTH_URL
    label = "authenticated" if api_key else "unauthenticated (rate-limited)"
    print(f"[*] downloading PhishTank dataset ({label})...")

    try:
        resp = requests.get(url, timeout=60, headers={"User-Agent": "Phantom/1.0"})
    except requests.RequestException as exc:
        raise RuntimeError(f"network error fetching PhishTank dataset: {exc}") from exc

    if resp.status_code == 509 or resp.status_code == 429:
        raise RuntimeError(
            "PhishTank rate limit hit. Get a free API key at "
            "https://www.phishtank.com/developer_info.php and set "
            "PHISHTANK_API_KEY in your .env, or wait before retrying."
        )
    if resp.status_code != 200:
        raise RuntimeError(f"PhishTank returned HTTP {resp.status_code}")

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_bytes(resp.content)
    print(f"[+] saved {len(resp.content):,} bytes to {CACHE_PATH}")
    return CACHE_PATH


def load_urls(csv_path: Path, limit: int | None = None) -> list[dict]:
    """Parse the PhishTank CSV into a list of {url, target, phish_id} dicts."""
    rows: list[dict] = []
    with csv_path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            url = row.get("url", "").strip()
            if not url:
                continue
            rows.append({
                "url": url,
                "target": row.get("target", "").strip() or "unknown",
                "phish_id": row.get("phish_id", ""),
            })
            if limit and len(rows) >= limit:
                break
    return rows


def benchmark(rows: list[dict]) -> None:
    """Run intel.phishing.analyze() against every URL, report hit rate.

    Pure local string analysis — no network calls to any of these URLs.
    """
    total = len(rows)
    if total == 0:
        print("[!] no rows loaded — dataset may be empty or malformed")
        return

    flagged = 0
    rule_hits: dict[str, int] = {}
    misses: list[dict] = []

    for row in rows:
        result = phishing.analyze(row["url"])
        if result.flagged:
            flagged += 1
            for indicator in result.indicators:
                # Bucket by the leading phrase so similar messages group together
                key = indicator.split(":")[0] if ":" in indicator else indicator
                rule_hits[key] = rule_hits.get(key, 0) + 1
        else:
            misses.append(row)

    hit_rate = (flagged / total) * 100
    print()
    print(f"[*] benchmarked {total:,} PhishTank-verified phishing URLs")
    print(f"[+] flagged by local heuristics: {flagged:,} ({hit_rate:.1f}%)")
    print(f"[-] missed: {total - flagged:,} ({100 - hit_rate:.1f}%)")
    print()

    if rule_hits:
        print("[*] which heuristics fired (top contributors):")
        for rule, count in sorted(rule_hits.items(), key=lambda kv: -kv[1]):
            print(f"    {count:>5}  {rule}")
        print()

    if misses:
        print(f"[*] sample of missed URLs (first 5 of {len(misses)}):")
        for row in misses[:5]:
            print(f"    - {row['url']}  (target brand: {row['target']})")
        print()
        print(
            "    These are real verified phishing URLs your current heuristics\n"
            "    don't flag — worth reviewing for patterns to add to intel/phishing.py."
        )


def main() -> int:
    load_dotenv(ROOT / ".env")
    api_key = os.getenv("PHISHTANK_API_KEY", "") or None

    limit = None
    if "--limit" in sys.argv:
        idx = sys.argv.index("--limit")
        if idx + 1 < len(sys.argv):
            limit = int(sys.argv[idx + 1])

    force = "--refresh" in sys.argv

    try:
        csv_path = fetch_dataset(api_key, force=force)
    except RuntimeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    rows = load_urls(csv_path, limit=limit)
    benchmark(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
