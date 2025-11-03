"""Tests for the scan data models."""

from nmap2report.models import (
    Address,
    Host,
    Hostname,
    Port,
    RunStats,
    Scan,
    Service,
)


def make_host() -> Host:
    return Host(
        status="up",
        addresses=[
            Address(addr="2001:db8::10", addrtype="ipv6"),
            Address(addr="192.0.2.10", addrtype="ipv4"),
            Address(addr="00:11:22:33:44:55", addrtype="mac", vendor="Acme"),
        ],
        hostnames=[Hostname(name="web01.example.test", type="PTR")],
    )


def test_service_label_includes_product_and_version() -> None:
    service = Service(name="http", product="nginx", version="1.24.0", extrainfo="Ubuntu")
    assert service.label == "http (nginx 1.24.0 Ubuntu)"


def test_service_label_without_details() -> None:
    assert Service(name="ftp").label == "ftp"
    assert Service().label == "unknown"
    assert Port(portid=1, protocol="tcp", state="open").service_label == "unknown"


def test_host_address_helpers() -> None:
    host = make_host()
    assert host.ipv4 == "192.0.2.10"
    assert host.ipv6 == "2001:db8::10"
    assert host.mac == "00:11:22:33:44:55"
    assert host.hostname == "web01.example.test"
    assert host.display_name == "web01.example.test"


def test_display_name_falls_back_to_address() -> None:
    assert Host(addresses=[Address(addr="192.0.2.5", addrtype="ipv4")]).display_name == (
        "192.0.2.5"
    )
    assert Host(addresses=[Address(addr="2001:db8::5", addrtype="ipv6")]).display_name == (
        "2001:db8::5"
    )
    assert Host().display_name == "unknown-host"


def test_open_ports_are_filtered_and_sorted() -> None:
    host = Host(
        status="up",
        ports=[
            Port(portid=443, protocol="tcp", state="closed"),
            Port(portid=8080, protocol="tcp", state="open"),
            Port(portid=22, protocol="tcp", state="open"),
            Port(portid=53, protocol="udp", state="open"),
        ],
    )
    assert [(port.portid, port.protocol) for port in host.open_ports] == [
        (22, "tcp"),
        (53, "udp"),
        (8080, "tcp"),
    ]
    assert host.open_port_count == 3


def test_scan_counts() -> None:
    scan = Scan(
        hosts=[
            make_host(),
            Host(status="down", addresses=[Address(addr="192.0.2.20", addrtype="ipv4")]),
        ]
    )
    scan.hosts[0].ports = [
        Port(portid=80, protocol="tcp", state="open"),
        Port(portid=443, protocol="tcp", state="closed"),
    ]
    assert scan.host_count == 2
    assert scan.up_host_count == 1
    assert scan.down_host_count == 1
    assert scan.open_port_count == 1


def test_defaults_are_independent() -> None:
    first = Scan()
    second = Scan()
    first.hosts.append(make_host())
    assert second.hosts == []
    assert isinstance(second.runstats, RunStats)
