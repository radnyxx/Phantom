"""Brute-force and suspicious-login pattern detection.

Two modes:
  - demo (default): generates a small, clearly-labeled synthetic dataset
    so the feature is explorable with zero setup.
  - --logfile: parses a real auth log.

Expected log line format (whitespace-separated, generic enough to match
many auth-log shapes after light preprocessing):

    2024-01-15T03:14:22 198.51.100.23 user=alice result=fail
    2024-01-15T03:14:24 198.51.100.23 user=bob result=fail
    2024-01-15T03:15:01 198.51.100.23 user=alice result=success

This is intentionally a simple, swappable format — production use would
adapt `parse_line` to the real log shape (syslog, auditd, cloud IAM export,
etc.) without touching the detection logic below it.
"""

from __future__ import annotations

import random
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+user=(?P<user>\S+)\s+result=(?P<result>success|fail)$"
)

# Detection thresholds — tunable, but defaults reflect common SOC heuristics.
FAILS_PER_IP_WINDOW = timedelta(minutes=5)
FAILS_PER_IP_THRESHOLD = 5        # N+ failed logins from one IP in the window
CRED_STUFFING_MIN_USERS = 4       # distinct usernames from one IP in the window
CRED_STUFFING_MAX_ATTEMPTS_PER_USER = 2  # but few attempts each (vs one user hammered)


@dataclass
class LoginEvent:
    timestamp: datetime
    ip: str
    user: str
    success: bool


@dataclass
class LoginAnalysisResult:
    total_events: int
    source: str  # "demo" or the logfile path
    brute_force_ips: list[dict] = field(default_factory=list)
    credential_stuffing_ips: list[dict] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return bool(self.brute_force_ips or self.credential_stuffing_ips)


def parse_line(line: str) -> LoginEvent | None:
    match = LINE_RE.match(line.strip())
    if not match:
        return None
    try:
        ts = datetime.fromisoformat(match.group("ts"))
    except ValueError:
        return None
    return LoginEvent(
        timestamp=ts,
        ip=match.group("ip"),
        user=match.group("user"),
        success=match.group("result") == "success",
    )


def load_logfile(path: str) -> list[LoginEvent]:
    events: list[LoginEvent] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            event = parse_line(line)
            if event:
                events.append(event)
    return events


def generate_demo_events(seed: int | None = None) -> list[LoginEvent]:
    """Synthetic dataset with one obvious brute-force IP, one credential-
    stuffing IP, and normal background noise. Clearly demo data — not a
    capture of real traffic.
    """
    rng = random.Random(seed)
    base = datetime(2024, 1, 15, 3, 0, 0)
    events: list[LoginEvent] = []

    # Background noise: normal scattered logins, mostly successful.
    normal_ips = ["203.0.113.10", "203.0.113.11", "203.0.113.12"]
    normal_users = ["jdoe", "asmith", "rwilliams", "tlee"]
    for i in range(15):
        events.append(LoginEvent(
            timestamp=base + timedelta(minutes=rng.randint(0, 120)),
            ip=rng.choice(normal_ips),
            user=rng.choice(normal_users),
            success=rng.random() > 0.1,
        ))

    # Brute force: one IP hammering one username with failures.
    bf_ip = "198.51.100.23"
    for i in range(9):
        events.append(LoginEvent(
            timestamp=base + timedelta(minutes=14, seconds=i * 12),
            ip=bf_ip,
            user="admin",
            success=False,
        ))

    # Credential stuffing: one IP, many distinct usernames, few attempts each.
    cs_ip = "203.0.113.99"
    for i, user in enumerate(["alice", "bob", "carla", "deepak", "elena", "farid"]):
        events.append(LoginEvent(
            timestamp=base + timedelta(minutes=40, seconds=i * 5),
            ip=cs_ip,
            user=user,
            success=False,
        ))

    events.sort(key=lambda e: e.timestamp)
    return events


def analyze(events: list[LoginEvent], source: str) -> LoginAnalysisResult:
    result = LoginAnalysisResult(total_events=len(events), source=source)

    by_ip: dict[str, list[LoginEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.ip].append(event)

    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        fails = [e for e in ip_events if not e.success]

        # Determine credential-stuffing shape first: many distinct users,
        # few attempts each. If this shape fits, classify the burst as
        # credential stuffing rather than also reporting it as a raw
        # brute-force hammer — they're different attacker behaviors and a
        # single burst should be reported as one or the other, not both.
        distinct_users = {e.user for e in fails}
        is_cred_stuffing_shape = False
        if len(distinct_users) >= CRED_STUFFING_MIN_USERS:
            max_attempts_per_user = max(
                (sum(1 for e in fails if e.user == u) for u in distinct_users),
                default=0,
            )
            if max_attempts_per_user <= CRED_STUFFING_MAX_ATTEMPTS_PER_USER:
                is_cred_stuffing_shape = True
                result.credential_stuffing_ips.append({
                    "ip": ip,
                    "distinct_users": len(distinct_users),
                    "max_attempts_per_user": max_attempts_per_user,
                })
                result.findings.append(
                    f"Credential-stuffing pattern: {ip} attempted "
                    f"{len(distinct_users)} distinct usernames with "
                    f"\u2264{CRED_STUFFING_MAX_ATTEMPTS_PER_USER} attempts each "
                    f"(low-and-slow spray, not a single-target hammer)"
                )

        if is_cred_stuffing_shape:
            continue

        # Sliding window scan for raw failed-attempt bursts (single/few
        # targets hammered repeatedly — the classic brute-force shape).
        for start_idx, start_event in enumerate(fails):
            window_end = start_event.timestamp + FAILS_PER_IP_WINDOW
            window_fails = [
                e for e in fails[start_idx:]
                if e.timestamp <= window_end
            ]
            if len(window_fails) >= FAILS_PER_IP_THRESHOLD:
                users_hit = sorted({e.user for e in window_fails})
                result.brute_force_ips.append({
                    "ip": ip,
                    "failed_attempts": len(window_fails),
                    "window_minutes": FAILS_PER_IP_WINDOW.total_seconds() / 60,
                    "users_targeted": users_hit,
                })
                result.findings.append(
                    f"Brute-force pattern: {ip} made {len(window_fails)} failed "
                    f"login attempts within {int(FAILS_PER_IP_WINDOW.total_seconds() / 60)} "
                    f"minutes (target: {', '.join(users_hit)})"
                )
                break  # one flagged window per IP is enough to report

    return result


def run(logfile: str | None = None) -> LoginAnalysisResult:
    if logfile:
        events = load_logfile(logfile)
        return analyze(events, source=logfile)
    events = generate_demo_events()
    return analyze(events, source="demo")
