"""Weight intel findings into a risk score and threat level."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from intel.queries import IntelResult


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskAssessment:
    """Scored threat assessment for a target."""

    target: str
    score: int
    level: RiskLevel
    breakdown: dict[str, int] = field(default_factory=dict)
    summary: str = ""


# Scoring weights from project spec
WEIGHT_KNOWN_MALICIOUS = 40
WEIGHT_SUSPICIOUS_PORTS = 15
WEIGHT_RECENT_WHOIS = 20


class RiskScorer:
    """Evaluates IntelResult findings and produces a risk assessment."""

    def score(self, intel: IntelResult) -> RiskAssessment:
        breakdown: dict[str, int] = {}
        total = 0

        if intel.known_malicious:
            breakdown["known_malicious"] = WEIGHT_KNOWN_MALICIOUS
            total += WEIGHT_KNOWN_MALICIOUS

        if intel.suspicious_ports:
            port_score = WEIGHT_SUSPICIOUS_PORTS * len(intel.suspicious_ports)
            breakdown["suspicious_ports"] = port_score
            total += port_score

        if intel.recent_whois_change:
            breakdown["recent_whois_change"] = WEIGHT_RECENT_WHOIS
            total += WEIGHT_RECENT_WHOIS

        vt = intel.sources.get("virustotal", {})
        if vt.get("suspicious", 0) > 0 and not intel.known_malicious:
            partial = min(20, vt["suspicious"] * 5)
            breakdown["vt_suspicious"] = partial
            total += partial

        abuse = intel.sources.get("abuseipdb", {})
        abuse_score = abuse.get("abuse_score", 0)
        if 25 <= abuse_score < 75:
            partial = int(abuse_score * 0.2)
            breakdown["abuseipdb_moderate"] = partial
            total += partial

        level = self._classify(total)
        summary = self._build_summary(intel, total, level)

        return RiskAssessment(
            target=intel.target,
            score=total,
            level=level,
            breakdown=breakdown,
            summary=summary,
        )

    def _classify(self, score: int) -> RiskLevel:
        if score >= 76:
            return RiskLevel.CRITICAL
        if score >= 51:
            return RiskLevel.HIGH
        if score >= 26:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _build_summary(self, intel: IntelResult, score: int, level: RiskLevel) -> str:
        parts = [f"Target '{intel.target}' assessed at {level.value} risk (score: {score})."]
        if intel.raw_findings:
            parts.append("Key findings: " + "; ".join(intel.raw_findings[:3]))
        if intel.errors:
            parts.append(f"Warnings: {len(intel.errors)} source(s) unavailable.")
        return " ".join(parts)
