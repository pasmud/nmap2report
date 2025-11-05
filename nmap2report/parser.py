"""Parse nmap XML output into the dataclasses from :mod:`nmap2report.models`.

The parser deliberately accepts the common variations produced by nmap: hosts
may be up or down, addresses may include IPv4, IPv6, and MAC entries, and many
elements are optional. Structural problems (malformed XML or a document that is
not an nmap scan) raise :class:`NmapParseError` with a message suitable for the
command line.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from os import PathLike
from pathlib import Path
from typing import Final

from .models import (
    Address,
    Host,
    Hostname,
    OSClass,
    OSMatch,
    Port,
    RunStats,
    Scan,
    ScanInfo,
    Script,
    Service,
)

_HOST_TAG: Final = "host"
_RUNSTATS_TAG: Final = "runstats"
_SCANINFO_TAG: Final = "scaninfo"


class NmapParseError(ValueError):
    """Raised when input cannot be parsed as an nmap XML scan."""


def parse_file(path: str | PathLike[str]) -> Scan:
    """Parse an nmap XML file and return a :class:`Scan`.

    Raises:
        NmapParseError: If the file is not well-formed XML or not an nmap scan.
        OSError: If the file cannot be read.
    """
    source = Path(path)
    try:
        tree = ET.parse(source)
    except ET.ParseError as exc:
        raise NmapParseError(f"invalid XML in {source}: {exc}") from exc
    return _parse_root(tree.getroot())


def parse_string(xml: str | bytes) -> Scan:
    """Parse nmap XML from a string or bytes and return a :class:`Scan`.

    Raises:
        NmapParseError: If the input is not well-formed XML or not an nmap scan.
    """
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise NmapParseError(f"invalid XML: {exc}") from exc
    return _parse_root(root)


def _parse_root(root: ET.Element) -> Scan:
    if root.tag != "nmaprun":
        raise NmapParseError(
            f"not an nmap XML document: expected <nmaprun> root, found <{root.tag}>"
        )

    scan = Scan(
        args=root.get("args", ""),
        start=_optional_int(root.get("start")),
        version=root.get("version", ""),
        xml_version=root.get("xmlversion", ""),
        scan_info=[
            _parse_scan_info(element) for element in root.findall(_SCANINFO_TAG)
        ],
        hosts=[_parse_host(element) for element in root.findall(_HOST_TAG)],
        runstats=_parse_runstats(root.find(_RUNSTATS_TAG)),
    )
    return scan


def _parse_scan_info(element: ET.Element) -> ScanInfo:
    return ScanInfo(
        scan_type=element.get("type", ""),
        protocol=element.get("protocol", ""),
        num_services=_int_attr(element, "numservices"),
        services=element.get("services", ""),
    )


def _parse_host(element: ET.Element) -> Host:
    status = element.find("status")
    ports: list[Port] = []
    ports_element = element.find("ports")
    if ports_element is not None:
        for port_element in ports_element.findall("port"):
            port = _parse_port(port_element)
            if port is not None:
                ports.append(port)

    return Host(
        status=status.get("state", "unknown") if status is not None else "unknown",
        addresses=[
            Address(
                addr=address.get("addr", ""),
                addrtype=address.get("addrtype", ""),
                vendor=address.get("vendor", ""),
            )
            for address in element.findall("address")
            if address.get("addr")
        ],
        hostnames=[
            Hostname(name=hostname.get("name", ""), type=hostname.get("type", ""))
            for hostname in element.findall("hostnames/hostname")
            if hostname.get("name")
        ],
        ports=ports,
        scripts=_parse_scripts(element),
        os_matches=_parse_os_matches(element),
        starttime=_optional_int(element.get("starttime")),
        endtime=_optional_int(element.get("endtime")),
        comment=element.get("comment", ""),
    )


def _parse_port(element: ET.Element) -> Port | None:
    portid = _optional_int(element.get("portid"))
    if portid is None:
        return None

    state = element.find("state")
    service = element.find("service")
    return Port(
        portid=portid,
        protocol=element.get("protocol", ""),
        state=state.get("state", "unknown") if state is not None else "unknown",
        reason=state.get("reason", "") if state is not None else "",
        service=(
            Service(
                name=service.get("name", ""),
                product=service.get("product", ""),
                version=service.get("version", ""),
                extrainfo=service.get("extrainfo", ""),
                tunnel=service.get("tunnel", ""),
                method=service.get("method", ""),
                conf=service.get("conf", ""),
            )
            if service is not None
            else None
        ),
        scripts=_parse_scripts(element),
    )


def _parse_scripts(element: ET.Element) -> list[Script]:
    return [
        Script(id=script.get("id", ""), output=script.get("output", ""))
        for script in element.findall("script")
        if script.get("id")
    ]


def _parse_os_matches(element: ET.Element) -> list[OSMatch]:
    os_element = element.find("os")
    if os_element is None:
        return []

    matches: list[OSMatch] = []
    for match in os_element.findall("osmatch"):
        name = match.get("name", "")
        if not name:
            continue
        matches.append(
            OSMatch(
                name=name,
                accuracy=_int_attr(match, "accuracy"),
                os_classes=[
                    OSClass(
                        os_type=osclass.get("type", ""),
                        vendor=osclass.get("vendor", ""),
                        osfamily=osclass.get("osfamily", ""),
                        osgen=osclass.get("osgen", ""),
                        accuracy=_int_attr(osclass, "accuracy"),
                    )
                    for osclass in match.findall("osclass")
                ],
            )
        )
    return matches


def _parse_runstats(element: ET.Element | None) -> RunStats:
    if element is None:
        return RunStats()

    finished = element.find("finished")
    hosts = element.find("hosts")
    return RunStats(
        hosts_up=_int_attr(hosts, "up"),
        hosts_down=_int_attr(hosts, "down"),
        hosts_total=_int_attr(hosts, "total"),
        elapsed=_float_attr(finished, "elapsed"),
        exit_status=finished.get("exit", "") if finished is not None else "",
        finished_time=_optional_int(finished.get("time")) if finished is not None else None,
    )


def _int_attr(element: ET.Element | None, name: str, default: int = 0) -> int:
    if element is None:
        return default
    value = element.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _float_attr(element: ET.Element | None, name: str, default: float = 0.0) -> float:
    if element is None:
        return default
    value = element.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _optional_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
