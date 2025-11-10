"""Tests for the heuristic risk mapping."""

from __future__ import annotations

import pytest

from nmap2report.models import Host, Port, Scan, Service
from nmap2report.risk import (
    SEVERITY_ORDER,
    Severity,
    assess_host,
    assess_port,
    assess_scan,
)


def host_with(*ports: Port, status: str = "up") -> Host:
    return Host(
        status=status,
        addresses=[],
        hostnames=[],
        ports=list(ports),
    )


def open_port(portid: int, service: str = "", **service_fields: str) -> Port:
    return Port(
        portid=portid,
        protocol="tcp",
        state="open",
        service=Service(name=service, **service_fields),
    )


@pytest.mark.parametrize(
    ("portid", "expected"),
    [
        (23, Severity.HIGH),
        (21, Severity.MEDIUM),
        (513, Severity.HIGH),
        (5900, Severity.MEDIUM),
        (6379, Severity.HIGH),
        (27017, Severity.HIGH),
        (9200, Severity.HIGH),
        (2375, Severity.CRITICAL),
        (445, Severity.HIGH),
        (3389, Severity.HIGH),
    ],
)
def test_required_port_mappings(portid: int, expected: Severity) -> None:
    host = host_with(open_port(portid))
    finding = assess_port(host, host.ports[0])
    assert finding is not None
    assert finding.severity is expected
    assert finding.port == portid
    assert finding.rationale


def test_service_name_fallback_for_nonstandard_port() -> None:
    host = host_with(open_port(16379, service="redis"))
    finding = assess_port(host, host.ports[0])
    assert finding is not None
    assert finding.severity is Severity.HIGH


def test_unknown_ports_use_informational_fallback() -> None:
    host = host_with(open_port(4444, service="custom"), open_port(999))
    high_port = assess_port(host, host.ports[0])
    low_port = assess_port(host, host.ports[1])
    assert high_port is not None
    assert low_port is not None
    assert high_port.severity is Severity.INFO
    assert low_port.severity is Severity.LOW


def test_closed_and_filtered_ports_are_ignored() -> None:
    host = host_with(
        Port(portid=23, protocol="tcp", state="closed"),
        Port(portid=6379, protocol="tcp", state="filtered"),
        Port(portid=445, protocol="tcp", state="open|filtered"),
    )
    assert assess_host(host).findings == ()


def test_version_note_mentions_disclosure_without_cves() -> None:
    host = host_with(
        open_port(6379, service="redis", product="Redis", version="7.2.4")
    )
    finding = assess_port(host, host.ports[0])
    assert finding is not None
    assert "Version disclosure: Redis 7.2.4." in finding.note
    assert "No CVE matching" in finding.note
    assert "CVE-" not in finding.note


def test_assessment_sorting_counts_and_score() -> None:
    host = host_with(
        open_port(4444),
        open_port(3389, service="ms-wbt-server"),
        open_port(21, service="ftp"),
        open_port(2375, service="docker"),
        Port(portid=443, protocol="tcp", state="closed"),
    )
    assessment = assess_host(host)
    assert [finding.severity for finding in assessment.findings] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.INFO,
    ]
    assert assessment.counts == {
        Severity.INFO: 1,
        Severity.LOW: 0,
        Severity.MEDIUM: 1,
        Severity.HIGH: 1,
        Severity.CRITICAL: 1,
    }
    assert assessment.score == 10 + 7 + 4 + 0
    assert assessment.highest is Severity.CRITICAL
    assert SEVERITY_ORDER[0] is Severity.CRITICAL


def test_down_host_has_no_findings() -> None:
    host = host_with(open_port(23, service="telnet"), status="down")
    assessment = assess_host(host)
    assert assessment.findings == ()
    assert assessment.highest is None
    assert assessment.score == 0


def test_scan_aggregates_all_up_hosts() -> None:
    first = host_with(open_port(23, service="telnet"))
    second = host_with(open_port(3306, service="mysql"))
    down = host_with(open_port(2375, service="docker"), status="down")
    assessment = assess_scan(Scan(hosts=[first, second, down]))
    assert len(assessment.findings) == 2
    assert assessment.counts[Severity.HIGH] == 1
    assert assessment.counts[Severity.MEDIUM] == 1
    assert assessment.counts[Severity.CRITICAL] == 0
