"""Dataclasses for the subset of nmap XML consumed by the report renderers.

The classes are intentionally small and serializable-friendly: every field has
a sensible default (except identifiers), so partial nmap output can still be
represented without special cases in the renderers.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Script:
    """An NSE script result attached to a host or port."""

    id: str
    output: str = ""


@dataclass(slots=True)
class Service:
    """Service fingerprint data reported by nmap for a port."""

    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    method: str = ""
    conf: str = ""

    @property
    def label(self) -> str:
        """Return a compact human-readable service label."""
        base = self.name or "unknown"
        details = " ".join(
            part for part in (self.product, self.version, self.extrainfo) if part
        )
        return f"{base} ({details})" if details else base


@dataclass(slots=True)
class Port:
    """A scanned port and the service/script data nmap associated with it."""

    portid: int
    protocol: str
    state: str
    reason: str = ""
    service: Service | None = None
    scripts: list[Script] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        """Whether nmap definitively reported the port as open."""
        return self.state == "open"

    @property
    def service_label(self) -> str:
        """Return the service label or ``unknown`` when no service was detected."""
        return self.service.label if self.service else "unknown"


@dataclass(slots=True)
class OSClass:
    """One OS classification within an nmap OS match."""

    os_type: str = ""
    vendor: str = ""
    osfamily: str = ""
    osgen: str = ""
    accuracy: int = 0


@dataclass(slots=True)
class OSMatch:
    """An nmap OS fingerprint match, optionally with detailed classifications."""

    name: str = ""
    accuracy: int = 0
    os_classes: list[OSClass] = field(default_factory=list)


@dataclass(slots=True)
class Hostname:
    """A hostname reported for a host, for example a PTR record."""

    name: str
    type: str = ""


@dataclass(slots=True)
class Address:
    """An address associated with a host (IPv4, IPv6, or MAC)."""

    addr: str
    addrtype: str = ""
    vendor: str = ""


@dataclass(slots=True)
class Host:
    """A scanned host, its addresses, ports, scripts, and OS matches."""

    status: str = "unknown"
    addresses: list[Address] = field(default_factory=list)
    hostnames: list[Hostname] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    scripts: list[Script] = field(default_factory=list)
    os_matches: list[OSMatch] = field(default_factory=list)
    starttime: int | None = None
    endtime: int | None = None
    comment: str = ""

    @property
    def is_up(self) -> bool:
        """Whether the host responded during the scan."""
        return self.status == "up"

    def address_for(self, addrtype: str) -> str:
        """Return the first address of *addrtype*, or an empty string."""
        for address in self.addresses:
            if address.addrtype == addrtype:
                return address.addr
        return ""

    @property
    def ipv4(self) -> str:
        """The first IPv4 address, or an empty string."""
        return self.address_for("ipv4")

    @property
    def ipv6(self) -> str:
        """The first IPv6 address, or an empty string."""
        return self.address_for("ipv6")

    @property
    def mac(self) -> str:
        """The first MAC address, or an empty string."""
        return self.address_for("mac")

    @property
    def hostname(self) -> str:
        """The first hostname, or an empty string."""
        return self.hostnames[0].name if self.hostnames else ""

    @property
    def display_name(self) -> str:
        """A stable label for the host, preferring hostname then IP addresses."""
        for candidate in (self.hostname, self.ipv4, self.ipv6, self.mac):
            if candidate:
                return candidate
        return "unknown-host"

    @property
    def open_ports(self) -> list[Port]:
        """Ports explicitly reported open, sorted by port number and protocol."""
        return sorted(
            (port for port in self.ports if port.is_open),
            key=lambda port: (port.portid, port.protocol),
        )

    @property
    def open_port_count(self) -> int:
        """Number of ports explicitly reported open on this host."""
        return sum(1 for port in self.ports if port.is_open)


@dataclass(slots=True)
class RunStats:
    """Scan completion statistics from the nmap ``runstats`` element."""

    hosts_up: int = 0
    hosts_down: int = 0
    hosts_total: int = 0
    elapsed: float = 0.0
    exit_status: str = ""
    finished_time: int | None = None


@dataclass(slots=True)
class ScanInfo:
    """One ``scaninfo`` entry describing the scan technique used."""

    scan_type: str = ""
    protocol: str = ""
    num_services: int = 0
    services: str = ""


@dataclass(slots=True)
class Scan:
    """A complete parsed nmap scan."""

    args: str = ""
    start: int | None = None
    version: str = ""
    xml_version: str = ""
    scan_info: list[ScanInfo] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    runstats: RunStats = field(default_factory=RunStats)

    @property
    def host_count(self) -> int:
        """Number of hosts present in the scan output."""
        return len(self.hosts)

    @property
    def up_host_count(self) -> int:
        """Number of hosts with an ``up`` status."""
        return sum(1 for host in self.hosts if host.is_up)

    @property
    def down_host_count(self) -> int:
        """Number of hosts with a non-``up`` status."""
        return sum(1 for host in self.hosts if not host.is_up)

    @property
    def open_port_count(self) -> int:
        """Total number of open ports across all hosts."""
        return sum(host.open_port_count for host in self.hosts)
