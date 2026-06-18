"""Zero-key threat intelligence — DNS blocklists, DROP, RDAP, URLScan public."""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import requests

if TYPE_CHECKING:
    from intel.queries import IntelResult

ROOT = Path(__file__).resolve().parent.parent
DROP_CACHE = ROOT / "data" / "feeds" / "drop_cache.json"
DROP_URL = "https://www.spamhaus.org/drop/drop_v4.json"
CACHE_MAX_AGE = 86400  # 24 hours

IP_DNSBL_ZONES = ("zen.spamhaus.org", "bl.spamcop.net")
DOMAIN_DNSBL_ZONES = ("dbl.spamhaus.org",)

PUBLIC_RESOLVER_CODES = {"127.255.255.254", "127.255.255.255"}


def _reverse_ip(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def _dnsbl_lookup(host: str) -> tuple[bool | None, str | None]:
    """Return (listed, return_code). None means unknown (e.g. public resolver blocked)."""
    try:
        code = socket.gethostbyname(host)
        if code in PUBLIC_RESOLVER_CODES:
            return None, code
        if code.startswith("127.0.0."):
            return True, code
        return False, code
    except socket.gaierror:
        return False, None


def _load_drop_cidrs(session: requests.Session) -> list[str]:
    """Load DROP CIDRs from cache; refresh if missing or stale."""
    cidrs: list[str] = []
    stale = True

    if DROP_CACHE.exists():
        try:
            data = json.loads(DROP_CACHE.read_text(encoding="utf-8"))
            fetched = data.get("fetched_at", 0)
            cidrs = data.get("cidrs", [])
            stale = (time.time() - fetched) > CACHE_MAX_AGE
        except (json.JSONDecodeError, OSError):
            stale = True

    if not cidrs or stale:
        try:
            resp = session.get(DROP_URL, timeout=30)
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
                }),
                encoding="utf-8",
            )
        except (requests.RequestException, json.JSONDecodeError, KeyError, OSError):
            if not cidrs:
                return []

    return cidrs


def _ip_in_drop(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _parse_rdap_date(value: str) -> float | None:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(value.replace("+0000", "Z"), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    return None


class FreeThreatIntel:
    """Populate IntelResult using free, no-signup sources."""

    def __init__(self, session: requests.Session) -> None:
        self.session = session
        self._drop_cidrs: list[str] | None = None

    @property
    def drop_cidrs(self) -> list[str]:
        if self._drop_cidrs is None:
            self._drop_cidrs = _load_drop_cidrs(self.session)
        return self._drop_cidrs

    def enrich(self, target: str, target_type: str, result: IntelResult) -> None:
        if target_type == "ip":
            self._check_ip(target, result)
        elif target_type == "domain":
            self._check_domain(target, result)
            self._check_urlscan(target, result)
        elif target_type == "url":
            self._check_urlscan(target, result)
        elif target_type == "hash":
            pass  # handled by hashcheck C extension in phantom.py

    def _check_ip(self, ip: str, result: IntelResult) -> None:
        listed_by: list[str] = []
        resolver_blocked = False

        for zone in IP_DNSBL_ZONES:
            host = f"{_reverse_ip(ip)}.{zone}"
            listed, code = _dnsbl_lookup(host)
            if listed is None:
                resolver_blocked = True
                continue
            if listed:
                listed_by.append(zone)

        result.sources["dnsbl"] = {
            "listed": bool(listed_by),
            "zones": listed_by,
            "resolver_blocked": resolver_blocked,
        }

        if listed_by:
            result.known_malicious = True
            result.raw_findings.append(f"DNS blocklist: listed on {', '.join(listed_by)}")

        if resolver_blocked and not listed_by:
            result.errors.append(
                "DNS blocklist: queries blocked by public DNS resolver — "
                "results may be incomplete"
            )

        if self.drop_cidrs and _ip_in_drop(ip, self.drop_cidrs):
            result.sources["spamhaus_drop"] = {"listed": True}
            result.known_malicious = True
            result.raw_findings.append("Spamhaus DROP: IP in hijacked/malicious netblock")
        elif self.drop_cidrs:
            result.sources["spamhaus_drop"] = {"listed": False}

    def _check_domain(self, domain: str, result: IntelResult) -> None:
        listed_by: list[str] = []
        resolver_blocked = False

        for zone in DOMAIN_DNSBL_ZONES:
            host = f"{domain}.{zone}"
            listed, code = _dnsbl_lookup(host)
            if listed is None:
                resolver_blocked = True
                continue
            if listed:
                listed_by.append(zone)

        result.sources["dnsbl"] = {
            "listed": bool(listed_by),
            "zones": listed_by,
            "resolver_blocked": resolver_blocked,
        }

        if listed_by:
            result.known_malicious = True
            result.raw_findings.append(f"DNS blocklist: domain listed on {', '.join(listed_by)}")

        if resolver_blocked and not listed_by:
            result.errors.append(
                "DNS blocklist: queries blocked by public DNS resolver — "
                "results may be incomplete"
            )

        self._check_rdap(domain, result)

    def _check_rdap(self, domain: str, result: IntelResult) -> None:
        try:
            resp = self.session.get(
                f"https://rdap.org/domain/{domain}",
                timeout=15,
                headers={"Accept": "application/rdap+json"},
            )
            if resp.status_code == 404:
                result.sources["rdap"] = {"status": "not_found"}
                return
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            result.errors.append(f"RDAP: {exc}")
            return

        events = data.get("events", [])
        registration_ts = None
        last_changed_ts = None

        for event in events:
            action = event.get("eventAction", "")
            date_str = event.get("eventDate", "")
            ts = _parse_rdap_date(date_str) if date_str else None
            if ts is None:
                continue
            if action == "registration":
                registration_ts = ts
            elif action in ("last changed", "last update of RDAP database"):
                last_changed_ts = ts

        ref_ts = last_changed_ts or registration_ts
        age_days = None
        if ref_ts:
            age_days = (time.time() - ref_ts) / 86400

        rdap_info: dict[str, Any] = {"status": data.get("status", [])}
        if registration_ts:
            rdap_info["registered"] = datetime.fromtimestamp(
                registration_ts, tz=timezone.utc
            ).strftime("%Y-%m-%d")
        if age_days is not None:
            rdap_info["age_days"] = round(age_days, 1)

        result.sources["rdap"] = rdap_info

        if age_days is not None and age_days < 30:
            result.recent_whois_change = True
            result.raw_findings.append(
                f"RDAP: domain registered/changed within 30 days ({round(age_days)}d old)"
            )

    def _check_urlscan(self, target: str, result: IntelResult) -> None:
        if target.startswith("http"):
            search_target = target
        else:
            search_target = f"http://{target}"

        try:
            resp = self.session.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"page.url:{search_target}"},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            result.errors.append(f"URLScan.io (public): {exc}")
            return

        results = data.get("results", [])
        verdicts = []
        for entry in results[:5]:
            task = entry.get("task", {})
            verdicts.append({
                "url": task.get("url", ""),
                "time": task.get("time", ""),
                "score": entry.get("score"),
            })

        result.sources["urlscan"] = {
            "scans": verdicts,
            "total": data.get("total", 0),
            "auth": "public",
        }

        for entry in results[:3]:
            if entry.get("score", 0) >= 50:
                result.known_malicious = True
                result.raw_findings.append("URLScan.io: high-risk scan result detected")
                break
