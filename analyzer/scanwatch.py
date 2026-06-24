"""Port-scan signature detection from connection logs.

This is the defensive counterpart to `intel/portscan.py`. Where that
module *probes* a remote target the user supplies, this module *recognizes*
when something else has been scanning a host the user controls, by looking
at connection-log lines.

Two modes:
  - demo (default): synthetic dataset with one obvious scanner.
  - --logfile: parses a real connection/firewall log.

Expected log line format:

    2024-01-15T03:14:22 198.51.100.23 -> 10.0.0.5:22
    2024-01-15T03:14:22 198.51.100.23 -> 10.0.0.5:23
    2024-01-15T03:14:23 198.51.100.23 -> 10.0.0.5:80

As with logscan.py, this is a simple swappable format — adapt `parse_line`
to match real firewall/netflow export shapes without touching detection.
"""

from __future__ import annotations

import random
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<src>\d{1,3}(?:\.\d{1,3}){3})\s*->\s*"
    r"(?P<dst>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{1,5})$"
)

SCAN_WINDOW = timedelta(seconds=30)
DISTINCT_PORTS_THRESHOLD = 6   # N+ distinct ports from one source in the window
SEQUENTIAL_RUN_THRESHOLD = 4   # N+ strictly-increasing-by-1 ports = textbook sweep


@dataclass
class ConnectionEvent:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    port: int


@dataclass
class ScanAnalysisResult:
    total_events: int
    source: str  # "demo" or the logfile path
    scanners: list[dict] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return bool(self.scanners)


def parse_line(line: str) -> ConnectionEvent | None:
    match = LINE_RE.match(line.strip())
    if not match:
        return None
    try:
        ts = datetime.fromisoformat(match.group("ts"))
    except ValueError:
        return None
    return ConnectionEvent(
        timestamp=ts,
        src_ip=match.group("src"),
        dst_ip=match.group("dst"),
        port=int(match.group("port")),
    )


def load_logfile(path: str) -> list[ConnectionEvent]:
    events: list[ConnectionEvent] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            event = parse_line(line)
            if event:
                events.append(event)
    return events


def generate_demo_events(seed: int | None = None) -> list[ConnectionEvent]:
    """Synthetic dataset with one obvious port sweep against a single host,
    plus normal background connection noise. Clearly demo data.
    """
    rng = random.Random(seed)
    base = datetime(2024, 1, 15, 3, 0, 0)
    events: list[ConnectionEvent] = []
    host = "10.0.0.5"

    # Background noise: normal clients hitting normal service ports.
    normal_ports = [80, 443, 443, 80, 22]
    normal_ips = ["203.0.113.10", "203.0.113.11", "203.0.113.12"]
    for i in range(12):
        events.append(ConnectionEvent(
            timestamp=base + timedelta(minutes=rng.randint(0, 60)),
            src_ip=rng.choice(normal_ips),
            dst_ip=host,
            port=rng.choice(normal_ports),
        ))

    # Scan: one source IP sweeping sequential low ports rapid-fire.
    scanner_ip = "198.51.100.23"
    for i, port in enumerate(range(20, 30)):
        events.append(ConnectionEvent(
            timestamp=base + timedelta(minutes=14, seconds=i * 2),
            src_ip=scanner_ip,
            dst_ip=host,
            port=port,
        ))

    events.sort(key=lambda e: e.timestamp)
    return events


def _longest_sequential_run(ports: list[int]) -> int:
    """Length of the longest run of strictly-increasing-by-1 ports, in the
    order they were observed — the signature of a textbook linear sweep.
    """
    if not ports:
        return 0
    longest = current = 1
    for prev, nxt in zip(ports, ports[1:]):
        if nxt == prev + 1:
            current += 1
            longest = max(longest, current)
        else:
            current = 1
    return longest


def analyze(events: list[ConnectionEvent], source: str) -> ScanAnalysisResult:
    result = ScanAnalysisResult(total_events=len(events), source=source)

    by_src_dst: dict[tuple[str, str], list[ConnectionEvent]] = defaultdict(list)
    for event in events:
        by_src_dst[(event.src_ip, event.dst_ip)].append(event)

    for (src, dst), pair_events in by_src_dst.items():
        pair_events.sort(key=lambda e: e.timestamp)

        for start_idx, start_event in enumerate(pair_events):
            window_end = start_event.timestamp + SCAN_WINDOW
            window_events = [
                e for e in pair_events[start_idx:]
                if e.timestamp <= window_end
            ]
            distinct_ports = sorted({e.port for e in window_events})

            if len(distinct_ports) >= DISTINCT_PORTS_THRESHOLD:
                run_len = _longest_sequential_run([e.port for e in window_events])
                pattern = "sequential sweep" if run_len >= SEQUENTIAL_RUN_THRESHOLD else "scattered probe"
                result.scanners.append({
                    "src_ip": src,
                    "dst_ip": dst,
                    "distinct_ports": len(distinct_ports),
                    "window_seconds": SCAN_WINDOW.total_seconds(),
                    "pattern": pattern,
                    "ports_sample": distinct_ports[:15],
                })
                result.findings.append(
                    f"Port-scan signature: {src} touched {len(distinct_ports)} distinct "
                    f"ports on {dst} within {int(SCAN_WINDOW.total_seconds())}s ({pattern})"
                )
                break  # one flagged window per (src, dst) pair is enough

    return result


def run(logfile: str | None = None) -> ScanAnalysisResult:
    if logfile:
        events = load_logfile(logfile)
        return analyze(events, source=logfile)
    events = generate_demo_events()
    return analyze(events, source="demo")
