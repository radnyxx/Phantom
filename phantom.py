#!/usr/bin/env python3
"""Phantom — threat intelligence CLI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.text import Text

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


def execute_scan_pipeline(target: str, args: argparse.Namespace, hashcheck_mod: any) -> int:
    """Encapsulated business logic for running a single target profile scan."""
    hash_result = None
    intel_instance = ThreatIntel()
    target_type = intel_instance.classify_target(target)

    if target_type == "hash" or args.hash_only:
        if hashcheck_mod is not None:
            hash_result = check_hash(hashcheck_mod, target)
            if args.hash_only:
                status = "KNOWN IOC" if hash_result["found"] else "clean"
                print(f"Hash: {target}")
                return 0 if not hash_result["found"] else 2

    intel = ThreatIntel(portscan_enabled=not args.no_portscan)
    if not args.hash_only:
        intel_result = intel.query(target)
    else:
        from intel.queries import IntelResult
        intel_result = IntelResult(target=target, target_type="hash")

    if target_type == "hash" and hash_result is None and hashcheck_mod:
        hash_result = check_hash(hashcheck_mod, target)
        if hash_result and hash_result["found"]:
            intel_result.known_malicious = True
            intel_result.raw_findings.append("Local IOC database: hash matched known malware")

    assessment = RiskScorer().score(intel_result)

    if not args.no_dashboard:
        show_dashboard(intel_result, assessment, hash_result)

    write_markdown_report(intel_result, assessment, args.output, hash_result)
    return 2 if assessment.level.value in ("HIGH", "CRITICAL") else 0


def run_interactive_loop(args: argparse.Namespace, hashcheck_mod: any):
    """The signature, flat pixel-style shell workspace."""
    console = Console()
    console.clear()
    

    banner = Text()
    banner.append("PHANTOM", style="bold #e07a5f")
    banner.append(" › Threat Intelligence Environment\n", style="dim")
    console.print(banner)
    console.print("[dim]Type 'exit' or press Ctrl+C to drop out of the session.[/dim]\n")
    
    while True:
        try:
            target = console.input("[bold #e07a5f]❯[/bold #e07a5f] Enter target (IP/Domain/URL): ").strip()
            
            if not target:
                continue
            if target.lower() in ("exit", "quit"):
                console.print("\n[dim]Session closed.[/dim]")
                break
                
            console.print(f" [dim]▵ Indexing threat matrices for {target}...[/dim]")
            
            # Run the scanning process dynamically inside the interactive shell
            execute_scan_pipeline(target, args, hashcheck_mod)
            console.print()  # Vertical padding space before drawing the next interactive prompt
            
        except (KeyboardInterrupt, EOFError):
            console.print("\n\n[dim]Session terminated cleanly. Goodbye![/dim]")
            sys.exit(0)


def main() -> int:
    load_dotenv(ROOT / ".env")

    parser = argparse.ArgumentParser(
        prog="phantom",
        description="Phantom — query threat intel APIs, score risk, and report findings.",
    )

    parser.add_argument("target", nargs="?", default=None, help="IP, domain, URL, or file hash to investigate")
    parser.add_argument("-o", "--output", default=str(DEFAULT_REPORT), help="Markdown report path")
    parser.add_argument("--no-dashboard", action="store_true", help="Skip the rich terminal dashboard")
    parser.add_argument("--hash-only", action="store_true", help="Only run local C hash check")
    parser.add_argument("--no-portscan", action="store_true", help="Skip local TCP port probing")
    args = parser.parse_args()

    hashcheck_mod, _ = load_hashcheck()


    if args.target is None:
        run_interactive_loop(args, hashcheck_mod)
        return 0
    else:
        mode = "enhanced" if ThreatIntel().has_api_keys else "free (zero-key)"
        print(f"[*] Querying threat intel for: {args.target} [{mode} mode]")
        return execute_scan_pipeline(args.target, args, hashcheck_mod)


if __name__ == "__main__":
    sys.exit(main())
