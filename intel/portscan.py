"""Local TCP port probe for suspicious open ports."""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING

from intel.constants import SUSPICIOUS_PORTS

if TYPE_CHECKING:
    from intel.queries import IntelResult

PROBE_TIMEOUT = 1.0


def probe_ports(ip: str, result: IntelResult) -> None:
    """Probe suspicious ports via TCP connect; populate IntelResult."""
    open_ports: list[int] = []

    for port in sorted(SUSPICIOUS_PORTS):
        try:
            with socket.create_connection((ip, port), timeout=PROBE_TIMEOUT):
                open_ports.append(port)
        except (OSError, socket.timeout):
            continue

    result.sources["portscan"] = {
        "probed": sorted(SUSPICIOUS_PORTS),
        "open": open_ports,
    }

    if open_ports:
        for port in open_ports:
            if port not in result.suspicious_ports:
                result.suspicious_ports.append(port)
        result.raw_findings.append(f"Port scan: suspicious ports open: {open_ports}")
