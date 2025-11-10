"""Documented exposure heuristics for open ports.

This module is **not a vulnerability scanner**. It maps well-known exposed
services to a coarse severity level and explains the reasoning. A finding means
"this service deserves attention", not "this host is vulnerable". Version
strings reported by nmap are surfaced as context only; no CVE lookup, exploit
matching, or exploitability claim is made.

The mapping is intentionally small and auditable. Unknown ports below 1024 are
reported as low severity, while unknown high-numbered ports are informational,
because high ports are commonly used by application services that still deserve
a quick confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final

from .models import Host, Port, Scan, Service


class Severity(str, Enum):
    """Coarse severity levels used by the exposure heuristics."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank where larger values are more severe."""
        return _SEVERITY_RANKS[self]

    @property
    def weight(self) -> int:
        """Score contribution used by the aggregate heuristic score."""
        return _SEVERITY_WEIGHTS[self]


_SEVERITY_RANKS: Final = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_SEVERITY_WEIGHTS: Final = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 4,
    Severity.HIGH: 7,
    Severity.CRITICAL: 10,
}

#: Display order, most severe first.
SEVERITY_ORDER: Final[tuple[Severity, ...]] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


@dataclass(frozen=True, slots=True)
class PortRule:
    """A severity and rationale for a known exposed service."""

    severity: Severity
    rationale: str


@dataclass(frozen=True, slots=True)
class RiskFinding:
    """A single exposure finding for one open port."""

    host: str
    port: int
    protocol: str
    service: str
    severity: Severity
    rationale: str
    note: str = ""


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Aggregated findings for a host or an entire scan."""

    findings: tuple[RiskFinding, ...]

    @property
    def counts(self) -> dict[Severity, int]:
        """Finding counts for every severity, including zero counts."""
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def score(self) -> int:
        """Sum of severity weights; useful only for rough prioritization."""
        return sum(finding.severity.weight for finding in self.findings)

    @property
    def highest(self) -> Severity | None:
        """The most severe finding level, or ``None`` when there are no findings."""
        return self.findings[0].severity if self.findings else None


_TELNET = PortRule(
    Severity.HIGH,
    "Telnet sends credentials and session data in cleartext.",
)
_FTP = PortRule(
    Severity.MEDIUM,
    "FTP often permits anonymous access and sends credentials in cleartext.",
)
_SSH = PortRule(
    Severity.LOW,
    "Remote shell exposed; restrict source networks and prefer key authentication.",
)
_RLOGIN = PortRule(
    Severity.HIGH,
    "rlogin provides cleartext remote login and weak host-based trust.",
)
_REXEC = PortRule(
    Severity.HIGH,
    "rexec permits remote command execution with weak host-based trust.",
)
_RSH = PortRule(
    Severity.HIGH,
    "rsh permits remote command execution with weak host-based trust.",
)
_VNC = PortRule(
    Severity.MEDIUM,
    "VNC is frequently deployed with no authentication or a weak password.",
)
_REDIS = PortRule(
    Severity.HIGH,
    "Redis commonly allows unauthenticated clients to read data and run commands.",
)
_MONGODB = PortRule(
    Severity.HIGH,
    "MongoDB deployments may allow unauthenticated access to stored data.",
)
_ELASTICSEARCH = PortRule(
    Severity.HIGH,
    "The Elasticsearch API may expose or accept data without authentication.",
)
_DOCKER_API = PortRule(
    Severity.CRITICAL,
    "An unauthenticated Docker API grants container control and often host control.",
)
_SMB = PortRule(
    Severity.HIGH,
    "SMB can expose shares and credential material; restrict it to trusted networks.",
)
_RDP = PortRule(
    Severity.HIGH,
    "RDP is exposed to brute force and repeated pre-authentication attacks.",
)
_HTTP = PortRule(
    Severity.INFO,
    "Plaintext HTTP is reachable; review the content and prefer HTTPS.",
)
_HTTPS = PortRule(
    Severity.INFO,
    "A TLS-wrapped web service is reachable; verify its certificate and protocols.",
)
_HTTP_ALT = PortRule(
    Severity.INFO,
    "An alternative HTTP service is reachable; confirm the application is intended to be public.",
)
_MYSQL = PortRule(
    Severity.MEDIUM,
    "A database service is exposed; restrict network access and review authentication.",
)
_POSTGRES = PortRule(
    Severity.MEDIUM,
    "A database service is exposed; restrict network access and review authentication.",
)
_MSSQL = PortRule(
    Severity.MEDIUM,
    "A database service is exposed; restrict network access and review authentication.",
)
_DOCKER_TLS = PortRule(
    Severity.MEDIUM,
    "The Docker API is reachable over TLS; verify client authentication is enforced.",
)

#: Port-based rules. Service names are used as a fallback for non-standard ports.
PORT_RULES: Final[dict[int, PortRule]] = {
    21: _FTP,
    22: _SSH,
    23: _TELNET,
    80: _HTTP,
    443: _HTTPS,
    445: _SMB,
    512: _REXEC,
    513: _RLOGIN,
    514: _RSH,
    1433: _MSSQL,
    2375: _DOCKER_API,
    2376: _DOCKER_TLS,
    3306: _MYSQL,
    3389: _RDP,
    5432: _POSTGRES,
    5900: _VNC,
    6379: _REDIS,
    8080: _HTTP_ALT,
    9200: _ELASTICSEARCH,
    27017: _MONGODB,
}

#: Service-name fallback rules, applied when the port has no explicit rule.
SERVICE_RULES: Final[dict[str, PortRule]] = {
    "telnet": _TELNET,
    "ftp": _FTP,
    "ssh": _SSH,
    "login": _RLOGIN,
    "rlogin": _RLOGIN,
    "exec": _REXEC,
    "rexec": _REXEC,
    "shell": _RSH,
    "rsh": _RSH,
    "vnc": _VNC,
    "redis": _REDIS,
    "mongodb": _MONGODB,
    "elasticsearch": _ELASTICSEARCH,
    "docker": _DOCKER_API,
    "microsoft-ds": _SMB,
    "netbios-ssn": _SMB,
    "ms-wbt-server": _RDP,
    "mysql": _MYSQL,
    "postgresql": _POSTGRES,
    "ms-sql-s": _MSSQL,
    "http": _HTTP,
    "https": _HTTPS,
    "http-proxy": _HTTP_ALT,
}

_UNKNOWN_HIGH_PORT = PortRule(
    Severity.INFO,
    "High-numbered port is exposed; confirm that this service is intended to be reachable.",
)
_UNKNOWN_LOW_PORT = PortRule(
    Severity.LOW,
    "Unclassified privileged port is exposed; review the service before exposing it.",
)


def _version_note(service: Service | None) -> str:
    if service is None:
        return ""
    details = " ".join(
        part for part in (service.product, service.version, service.extrainfo) if part
    )
    if not details:
        return ""
    return (
        f"Version disclosure: {details}. "
        "No CVE matching or vulnerability claim is made."
    )


def assess_port(host: Host, port: Port) -> RiskFinding | None:
    """Return a heuristic finding for an open *port*, or ``None`` if it is closed."""
    if not port.is_open:
        return None

    service = port.service
    service_name = service.name if service else ""
    rule = PORT_RULES.get(port.portid) or SERVICE_RULES.get(service_name)
    if rule is None:
        rule = _UNKNOWN_HIGH_PORT if port.portid >= 1024 else _UNKNOWN_LOW_PORT

    return RiskFinding(
        host=host.display_name,
        port=port.portid,
        protocol=port.protocol,
        service=port.service_label,
        severity=rule.severity,
        rationale=rule.rationale,
        note=_version_note(service),
    )


def assess_host(host: Host) -> RiskAssessment:
    """Assess all open ports on *host* and return findings sorted by severity."""
    if not host.is_up:
        return RiskAssessment(())

    findings = [
        finding
        for port in host.ports
        if (finding := assess_port(host, port)) is not None
    ]
    return RiskAssessment(_sort_findings(findings))


def assess_scan(scan: Scan) -> RiskAssessment:
    """Assess every up host in *scan* and aggregate the findings."""
    findings = [
        finding for host in scan.hosts for finding in assess_host(host).findings
    ]
    return RiskAssessment(_sort_findings(findings))


def _sort_findings(findings: list[RiskFinding]) -> tuple[RiskFinding, ...]:
    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                -finding.severity.rank,
                finding.host.lower(),
                finding.port,
                finding.protocol,
            ),
        )
    )
