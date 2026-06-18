#!/usr/bin/env python3
"""Phantom — threat intelligence CLI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

from analyzer import RiskScorer
from intel import ThreatIntel
from reporter import show_dashboard, write_markdown_report

ROOT = Path(__file__).resolve().parent
IOC_PATH = ROOT / "data" / "iocs.txt"
DEFAULT_REPORT = ROOT / "reports" / "report.md"


def load_hashcheck():
    """Load the C extension if built, otherwise return None."""
    try:
        import hashcheck
        count = hashcheck.load(str(IOC_PATH))
        return hashcheck, count
    except ImportError:
        return None, 0


def check_hash(hashcheck_mod, target: str) -> dict | None:
    if hashcheck_mod is None:
        return None
    found = hashcheck_mod.check(target)
    return {"hash": target, "found": found}


def main() -> int:
    load_dotenv(ROOT / ".env")

    parser = argparse.ArgumentParser(
        prog="phantom",
        description="Phantom — query threat intel APIs, score risk, and report findings.",
    )
    parser.add_argument("target", help="IP, domain, URL, or file hash to investigate")
    parser.add_argument(
        "-o", "--output",
        default=str(DEFAULT_REPORT),
        help="Markdown report output path (default: reports/report.md)",
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Skip the rich terminal dashboard",
    )
    parser.add_argument(
        "--hash-only",
        action="store_true",
        help="Only run local C hash check (skip API queries)",
    )
    parser.add_argument(
        "--no-portscan",
        action="store_true",
        help="Skip local TCP port probing (used when Shodan key is absent)",
    )
    args = parser.parse_args()

    hashcheck_mod, ioc_count = load_hashcheck()
    hash_result = None

    target_type = ThreatIntel().classify_target(args.target)

    if target_type == "hash" or args.hash_only:
        if hashcheck_mod is None:
            print("hashcheck C extension not built. Run: python setup.py build_ext --inplace")
            if args.hash_only:
                return 1
        else:
            hash_result = check_hash(hashcheck_mod, args.target)
            if args.hash_only:
                status = "KNOWN IOC" if hash_result["found"] else "clean"
                print(f"Hash: {args.target}")
                print(f"IOC database: {ioc_count} entries")
                print(f"Result: {status}")
                return 0 if not hash_result["found"] else 2

    intel = ThreatIntel(portscan_enabled=not args.no_portscan)
    if not args.hash_only:
        mode = "enhanced" if intel.has_api_keys else "free (zero-key)"
        print(f"[*] Querying threat intel for: {args.target} [{mode} mode]")
        intel_result = intel.query(args.target)
    else:
        from intel.queries import IntelResult
        intel_result = IntelResult(target=args.target, target_type="hash")

    if target_type == "hash" and hash_result is None and hashcheck_mod:
        hash_result = check_hash(hashcheck_mod, args.target)
        if hash_result and hash_result["found"]:
            intel_result.known_malicious = True
            intel_result.raw_findings.append("Local IOC database: hash matched known malware")

    assessment = RiskScorer().score(intel_result)

    if not args.no_dashboard:
        show_dashboard(intel_result, assessment, hash_result)

    report_path = write_markdown_report(
        intel_result, assessment, args.output, hash_result
    )
    print(f"\n[*] Markdown report written to: {report_path}")

    if assessment.level.value in ("HIGH", "CRITICAL"):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
