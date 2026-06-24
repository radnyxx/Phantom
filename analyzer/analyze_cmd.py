"""`phantom analyze` — log-based detection subcommand.

Runs the brute-force/credential-stuffing login analyzer and the port-scan
signature detector against either a real logfile or built-in demo data.

This is intentionally decoupled from the live-intel `query()` pipeline in
intel/queries.py: those analyzers reason over external reputation sources
for a single target, while this subcommand reasons over *your own* logs
for behavioral attack patterns. Different inputs, different question being
asked ("is this IP bad?" vs "does this traffic look like an attack?").

Usage:
    phantom analyze                                  # demo data, both analyzers
    phantom analyze --logins auth.log                # real login log, demo connections
    phantom analyze --connections fw.log --skip-logins
"""

from __future__ import annotations

import argparse
import sys

from analyzer import logscan, scanwatch


def build_analyze_parser() -> argparse.ArgumentParser:
    """Build the standalone parser for `phantom analyze ...` (argv[2:])."""
    parser = argparse.ArgumentParser(
        prog="phantom analyze",
        description="Detect brute-force, credential-stuffing, and port-scan patterns in logs.",
    )
    parser.add_argument(
        "--logins", dest="login_logfile", metavar="FILE", default=None,
        help="Auth log file to analyze (omit for built-in demo data)",
    )
    parser.add_argument(
        "--connections", dest="conn_logfile", metavar="FILE", default=None,
        help="Connection/firewall log file to analyze (omit for built-in demo data)",
    )
    parser.add_argument(
        "--skip-logins", action="store_true",
        help="Skip the login/brute-force analyzer",
    )
    parser.add_argument(
        "--skip-connections", action="store_true",
        help="Skip the port-scan analyzer",
    )
    return parser


def run_analyze_command(args: argparse.Namespace) -> int:
    """Entry point for `phantom analyze`. Returns a process exit code.

    Exit codes follow the same convention as the main scan pipeline:
      0 = ran clean, nothing flagged
      1 = ran but a source/logfile could not be read (inconclusive)
      2 = at least one pattern was flagged
    """
    any_flagged = False
    any_error = False

    if not getattr(args, "skip_logins", False):
        login_logfile = getattr(args, "login_logfile", None)
        try:
            login_result = logscan.run(logfile=login_logfile)
        except OSError as exc:
            print(f"[!] could not read login log: {exc}", file=sys.stderr)
            any_error = True
        else:
            _print_login_section(login_result)
            any_flagged = any_flagged or login_result.flagged

    if not getattr(args, "skip_connections", False):
        conn_logfile = getattr(args, "conn_logfile", None)
        try:
            scan_result = scanwatch.run(logfile=conn_logfile)
        except OSError as exc:
            print(f"[!] could not read connection log: {exc}", file=sys.stderr)
            any_error = True
        else:
            _print_scan_section(scan_result)
            any_flagged = any_flagged or scan_result.flagged

    if any_error:
        return 1
    return 2 if any_flagged else 0


def _print_login_section(result: logscan.LoginAnalysisResult) -> None:
    label = "demo data" if result.source == "demo" else result.source
    print(f"\n[*] login analysis — {result.total_events} events ({label})")
    if not result.flagged:
        print("[-] no brute-force or credential-stuffing patterns detected")
        return
    for finding in result.findings:
        print(f"[!] {finding}")


def _print_scan_section(result: scanwatch.ScanAnalysisResult) -> None:
    label = "demo data" if result.source == "demo" else result.source
    print(f"\n[*] connection analysis — {result.total_events} events ({label})")
    if not result.flagged:
        print("[-] no port-scan signatures detected")
        return
    for finding in result.findings:
        print(f"[!] {finding}")
