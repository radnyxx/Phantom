"""Heuristic phishing-URL / lookalike-domain detection.

Pure pattern analysis — no network calls. Looks at the *shape* of a URL or
domain the way a defender triaging an inbound link would: lookalike brand
names, IP-literal hosts, punycode tricks, excessive subdomain nesting,
credential-in-URL tricks, and known shortener services that hide the real
destination.

This module never fetches the URL. It only reasons about the string.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# Brands commonly impersonated in phishing campaigns. Matching a brand
# keyword inside a domain that is NOT that brand's actual registered domain
# is one of the strongest lookalike signals available without a live
# WHOIS/registration lookup.
WATCHED_BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "accounts.google.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com"},
    "facebook": {"facebook.com", "meta.com"},
    "netflix": {"netflix.com"},
    "bankofamerica": {"bankofamerica.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "irs": {"irs.gov"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "shorte.st", "cutt.ly", "rb.gy",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "work", "support", "loan",
    "win", "review", "tk", "gq", "ml", "cf",
}

IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
PUNYCODE_RE = re.compile(r"xn--", re.IGNORECASE)
HEX_HOST_RE = re.compile(r"^[0-9a-fA-F]{8,}$")


@dataclass
class PhishingFindings:
    """Result of heuristic phishing analysis on a single URL/domain."""

    target: str
    indicators: list[str] = field(default_factory=list)
    score: int = 0  # additive, fed into the main risk scorer

    @property
    def flagged(self) -> bool:
        return self.score > 0


def _extract_host(target: str) -> tuple[str, str, str]:
    """Return (host, path, full_target) regardless of whether a scheme was given."""
    candidate = target if "://" in target else f"http://{target}"
    parts = urlsplit(candidate)
    return parts.hostname or "", parts.path or "", target


def analyze(target: str) -> PhishingFindings:
    """Run all heuristics against a URL or bare domain string.

    Each triggered heuristic appends a human-readable indicator and a point
    value. Point values are deliberately modest (5-20) since these are
    *heuristics*, not confirmations — a single hit should nudge the score,
    not dominate it the way a confirmed VirusTotal/AbuseIPDB hit does.
    """
    host, path, raw = _extract_host(target)
    findings = PhishingFindings(target=raw)

    if not host:
        return findings

    host_lower = host.lower()

    # 1. IP literal as the host — legitimate brand sites essentially never
    # do this; it's a classic way to dodge domain-reputation checks.
    if IP_HOST_RE.match(host_lower):
        findings.indicators.append("URL uses a raw IP address instead of a domain name")
        findings.score += 15

    # 2. Punycode — used for homoglyph attacks (e.g. an "a" that's actually
    # Cyrillic а). Not inherently malicious, but rare in legitimate mail/links.
    if PUNYCODE_RE.search(host_lower):
        findings.indicators.append("Domain uses punycode encoding (possible homoglyph/lookalike trick)")
        findings.score += 20

    # 3. Credential-in-URL trick: http://real-looking-text@evil.com/...
    # Browsers historically rendered the part before '@' as if it were the
    # domain, which attackers exploited to disguise the real host.
    if "@" in raw.split("://")[-1].split("/")[0]:
        findings.indicators.append("URL contains an '@' before the host (userinfo obfuscation trick)")
        findings.score += 20

    # 4. Excessive subdomain nesting — e.g.
    # paypal.com.verify-account.security-update.ru
    labels = host_lower.split(".")
    if len(labels) >= 5:
        findings.indicators.append(f"Unusually deep subdomain nesting ({len(labels)} labels)")
        findings.score += 10

    # 5. Brand keyword present, but host is not that brand's real domain.
    for brand, real_domains in WATCHED_BRANDS.items():
        if brand in host_lower.replace("-", "").replace("_", ""):
            if not any(host_lower == d or host_lower.endswith("." + d) for d in real_domains):
                findings.indicators.append(
                    f"Domain references brand '{brand}' but does not match its known domain(s)"
                )
                findings.score += 25
                break  # one brand-mismatch hit is enough signal

    # 6. Known URL shortener — destination is hidden, can't be judged directly.
    if host_lower in KNOWN_SHORTENERS:
        findings.indicators.append(f"URL uses a known shortener ({host_lower}); real destination is hidden")
        findings.score += 10

    # 7. Suspicious / cheap bulk-registration TLD.
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        findings.indicators.append(f"TLD '.{tld}' is disproportionately associated with abuse")
        findings.score += 10

    # 8. Hex-string subdomain/host — sometimes used for auto-generated
    # phishing infrastructure or DGA-style domains.
    if labels and HEX_HOST_RE.match(labels[0]) and len(labels[0]) >= 8:
        findings.indicators.append("Leading label looks machine-generated (long hex string)")
        findings.score += 10

    # 9. Path mimics a login/verification flow on a non-brand domain —
    # weak signal alone, but compounds with a brand-mismatch hit above.
    if re.search(r"(login|verify|secure|account|update|confirm)", path.lower()) and findings.score >= 25:
        findings.indicators.append("Path contains credential-harvesting keywords alongside other indicators")
        findings.score += 5

    return findings
