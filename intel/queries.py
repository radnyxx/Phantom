"""Query threat intelligence APIs and free zero-key sources."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

import requests

from intel.constants import SUSPICIOUS_PORTS
from intel.free_sources import FreeThreatIntel
from intel.portscan import probe_ports

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
URL_RE = re.compile(r"^https?://", re.IGNORECASE)


@dataclass
class IntelResult:
    """Aggregated findings from all intel sources."""

    target: str
    target_type: str
    sources: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    known_malicious: bool = False
    suspicious_ports: list[int] = field(default_factory=list)
    recent_whois_change: bool = False
    raw_findings: list[str] = field(default_factory=list)


class ThreatIntel:
    """Queries API sources (optional) and free zero-key sources."""

    def __init__(self, portscan_enabled: bool = True) -> None:
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self.shodan_key = os.getenv("SHODAN_API_KEY", "")
        self.urlscan_key = os.getenv("URLSCAN_API_KEY", "")
        self.portscan_enabled = portscan_enabled
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Phantom/1.0"})
        self._free = FreeThreatIntel(self.session)

    @property
    def has_api_keys(self) -> bool:
        return bool(self.vt_key or self.abuse_key or self.shodan_key or self.urlscan_key)

    def classify_target(self, target: str) -> str:
        target = target.strip()
        if URL_RE.match(target):
            return "url"
        if IP_RE.match(target):
            return "ip"
        if HASH_RE.match(target):
            return "hash"
        if DOMAIN_RE.match(target):
            return "domain"
        return "unknown"

    def query(self, target: str) -> IntelResult:
        target = target.strip()
        target_type = self.classify_target(target)
        result = IntelResult(target=target, target_type=target_type)

        if target_type == "unknown":
            result.errors.append(f"Unrecognized target format: {target}")
            return result

        mode = "enhanced" if self.has_api_keys else "free"
        result.sources["mode"] = mode

        if self.has_api_keys:
            if target_type in ("ip", "domain", "hash"):
                self._query_virustotal(target, target_type, result)
            if target_type == "ip":
                self._query_abuseipdb(target, result)
                self._query_shodan(target, result)
            if target_type in ("url", "domain"):
                self._query_urlscan(target, result)
            if target_type == "domain":
                self._query_shodan_dns(target, result)
        else:
            self._free.enrich(target, target_type, result)

        # Free sources fill gaps when API keys are absent
        if not self.shodan_key and target_type == "ip" and self.portscan_enabled:
            probe_ports(target, result)

        if self.has_api_keys:
            if target_type == "ip" and not self.abuse_key:
                self._free._check_ip(target, result)
            if target_type == "domain" and not self.vt_key:
                self._free._check_domain(target, result)
            elif target_type == "domain" and not self.urlscan_key:
                self._free._check_urlscan(target, result)
            if target_type == "url" and not self.urlscan_key:
                self._free._check_urlscan(target, result)

        return result

    def _get(self, url: str, headers: dict | None = None, params: dict | None = None) -> dict | None:
        try:
            resp = self.session.get(url, headers=headers or {}, params=params or {}, timeout=15)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            return {"_error": str(exc)}

    def _query_virustotal(self, target: str, target_type: str, result: IntelResult) -> None:
        if not self.vt_key:
            return

        headers = {"x-apikey": self.vt_key}
        if target_type == "hash":
            url = f"https://www.virustotal.com/api/v3/files/{target}"
        elif target_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        else:
            url = f"https://www.virustotal.com/api/v3/domains/{target}"

        data = self._get(url, headers=headers)
        if data is None:
            result.sources["virustotal"] = {"status": "not_found"}
            return
        if "_error" in data:
            result.errors.append(f"VirusTotal: {data['_error']}")
            return

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        vt_result = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "reputation": attrs.get("reputation", 0),
        }
        result.sources["virustotal"] = vt_result

        if malicious > 0:
            result.known_malicious = True
            result.raw_findings.append(
                f"VirusTotal: {malicious} engines flagged as malicious"
            )
        if suspicious > 0:
            result.raw_findings.append(
                f"VirusTotal: {suspicious} engines flagged as suspicious"
            )

        whois_date = attrs.get("whois_date") or attrs.get("creation_date")
        if whois_date:
            import time
            age_days = (time.time() - whois_date) / 86400
            if age_days < 30:
                result.recent_whois_change = True
                result.raw_findings.append("VirusTotal: domain registered/changed within 30 days")

    def _query_abuseipdb(self, ip: str, result: IntelResult) -> None:
        if not self.abuse_key:
            return

        headers = {"Key": self.abuse_key, "Accept": "application/json"}
        data = self._get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        if not data or "_error" in data:
            result.errors.append(f"AbuseIPDB: {data.get('_error', 'unknown error') if data else 'no response'}")
            return

        entry = data.get("data", {})
        score = entry.get("abuseConfidenceScore", 0)
        result.sources["abuseipdb"] = {
            "abuse_score": score,
            "total_reports": entry.get("totalReports", 0),
            "country": entry.get("countryCode", ""),
            "isp": entry.get("isp", ""),
        }

        if score >= 75:
            result.known_malicious = True
            result.raw_findings.append(f"AbuseIPDB: abuse confidence {score}%")
        elif score >= 25:
            result.raw_findings.append(f"AbuseIPDB: moderate abuse confidence {score}%")

    def _query_shodan(self, ip: str, result: IntelResult) -> None:
        if not self.shodan_key:
            return

        data = self._get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": self.shodan_key})
        if not data or "_error" in data:
            result.errors.append(f"Shodan: {data.get('_error', 'unknown error') if data else 'no response'}")
            return

        ports = data.get("ports", [])
        open_ports = [p for p in ports if p in SUSPICIOUS_PORTS]
        result.sources["shodan"] = {
            "ports": ports,
            "os": data.get("os"),
            "org": data.get("org", ""),
            "vulns": list(data.get("vulns", {}).keys())[:5],
        }

        if open_ports:
            result.suspicious_ports.extend(open_ports)
            result.raw_findings.append(f"Shodan: suspicious ports open: {open_ports}")

    def _query_shodan_dns(self, domain: str, result: IntelResult) -> None:
        if not self.shodan_key or "shodan" in result.sources:
            return

        data = self._get(
            "https://api.shodan.io/dns/domain/" + domain,
            params={"key": self.shodan_key},
        )
        if not data or "_error" in data:
            return

        result.sources["shodan_dns"] = {
            "subdomains": data.get("subdomains", [])[:10],
            "tags": data.get("tags", []),
        }

    def _query_urlscan(self, target: str, result: IntelResult) -> None:
        if not self.urlscan_key:
            return

        headers = {"API-Key": self.urlscan_key, "Content-Type": "application/json"}
        search_target = target if URL_RE.match(target) else f"http://{target}"

        try:
            resp = self.session.get(
                "https://urlscan.io/api/v1/search/",
                headers=headers,
                params={"q": f"page.url:{search_target}"},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            result.errors.append(f"URLScan.io: {exc}")
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

        result.sources["urlscan"] = {"scans": verdicts, "total": data.get("total", 0), "auth": "api_key"}

        for entry in results[:3]:
            if entry.get("score", 0) >= 50:
                result.known_malicious = True
                result.raw_findings.append("URLScan.io: high-risk scan result detected")
                break
