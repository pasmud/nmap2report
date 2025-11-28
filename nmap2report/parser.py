"""Parse nmap XML output into the dataclasses from :mod:`nmap2report.models`.

The parser deliberately accepts the common variations produced by nmap: hosts
may be up or down, addresses may include IPv4, IPv6, and MAC entries, and many
elements are optional. Structural problems (malformed XML or a document that is
not an nmap scan) raise :class:`NmapParseError` with a message suitable for the
command line.
"""

from __future__ import annotations

import stat
import xml.etree.ElementTree as ET
from os import PathLike
from pathlib import Path
from typing import BinaryIO, Final
from xml.parsers import expat

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
MAX_XML_BYTES: Final = 16 * 1024 * 1024
MAX_XML_DEPTH: Final = 64
MAX_XML_ELEMENTS: Final = 100_000


class NmapParseError(ValueError):
    """Raised when input cannot be parsed as an nmap XML scan."""


def parse_file(path: str | PathLike[str]) -> Scan:
    """Parse an nmap XML file and return a :class:`Scan`.

    Raises:
        NmapParseError: If the file is not well-formed XML or not an nmap scan.
        OSError: If the file cannot be read.
    """
    source = Path(path)
    if not stat.S_ISREG(source.stat().st_mode):
        raise OSError("input must be a regular file")
    with source.open("rb") as stream:
        return parse_stream(stream)


def parse_stream(stream: BinaryIO) -> Scan:
    """Parse from a blocking binary stream without closing it.

    At most one byte past the XML size limit is read to detect oversized input.
    """
    data = bytearray()
    while len(data) <= MAX_XML_BYTES:
        chunk = stream.read(min(64 * 1024, MAX_XML_BYTES + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    return parse_string(bytes(data))


def parse_string(xml: str | bytes) -> Scan:
    """Parse nmap XML from a string or bytes and return a :class:`Scan`.

    Raises:
        NmapParseError: If the input is not well-formed XML or not an nmap scan.
    """
    if len(xml) > MAX_XML_BYTES:
        raise NmapParseError(f"XML exceeds the {MAX_XML_BYTES:,}-byte limit")
    if isinstance(xml, str):
        try:
            data = xml.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise NmapParseError("invalid Unicode in XML") from exc
    else:
        data = xml
    if len(data) > MAX_XML_BYTES:
        raise NmapParseError(f"XML exceeds the {MAX_XML_BYTES:,}-byte limit")
    return _parse_root(_parse_xml(data, "UTF-8" if isinstance(xml, str) else None))


def _parse_xml(data: bytes, encoding: str | None) -> ET.Element:
    """Enforce XML limits during parsing, before allocating a full tree."""
    # Keep literal names so a long namespace URI is never copied into every tag.
    parser = expat.ParserCreate(encoding)
    builder = ET.TreeBuilder()
    open_tags: list[str] = []
    elements = 0

    def start(name: str, attrs: dict[str, str]) -> None:
        nonlocal elements
        elements += 1
        if len(open_tags) >= MAX_XML_DEPTH:
            raise NmapParseError(f"XML exceeds the {MAX_XML_DEPTH}-level nesting limit")
        if elements > MAX_XML_ELEMENTS:
            raise NmapParseError(f"XML exceeds the {MAX_XML_ELEMENTS:,}-element limit")
        # A default namespace also makes this branch foreign to the nmap schema.
        if attrs.get("xmlns"):
            name = ":" + name
        open_tags.append(name)
        builder.start(name, attrs)

    def end(_name: str) -> None:
        builder.end(open_tags.pop())

    def doctype(
        name: str, system_id: str | None, public_id: str | None, has_subset: int
    ) -> None:
        if name != "nmaprun" or system_id is not None or public_id is not None or has_subset:
            raise NmapParseError("only a bare <!DOCTYPE nmaprun> declaration is allowed")

    def reject_external(*_args: object) -> int:
        raise NmapParseError("external XML entities are not allowed")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    # All supported fields are attributes; discard character data as it is parsed.
    parser.StartDoctypeDeclHandler = doctype
    parser.ExternalEntityRefHandler = reject_external
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(data, True)
    except NmapParseError:
        raise
    except (expat.ExpatError, LookupError, ValueError) as exc:
        raise NmapParseError(f"invalid XML: {exc}") from exc
    return builder.close()


def _parse_root(root: ET.Element) -> Scan:
    if root.tag != "nmaprun":
        raise NmapParseError(
            f"not an nmap XML document: expected <nmaprun> root, found <{root.tag:.80}>"
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
    return Host(
        status=status.get("state", "unknown") if status is not None else "unknown",
        addresses=_parse_addresses(element),
        hostnames=_parse_hostnames(element),
        ports=_parse_ports(element),
        scripts=_parse_scripts(element) + _parse_scripts(element, "hostscript/script"),
        os_matches=_parse_os_matches(element),
        starttime=_optional_int(element.get("starttime")),
        endtime=_optional_int(element.get("endtime")),
        comment=element.get("comment", ""),
    )


def _parse_addresses(element: ET.Element) -> list[Address]:
    return [
        Address(
            addr=address.get("addr", ""),
            addrtype=address.get("addrtype", ""),
            vendor=address.get("vendor", ""),
        )
        for address in element.findall("address")
        if address.get("addr")
    ]


def _parse_hostnames(element: ET.Element) -> list[Hostname]:
    return [
        Hostname(name=hostname.get("name", ""), type=hostname.get("type", ""))
        for hostname in element.findall("hostnames/hostname")
        if hostname.get("name")
    ]


def _parse_ports(element: ET.Element) -> list[Port]:
    ports_element = element.find("ports")
    if ports_element is None:
        return []

    ports: list[Port] = []
    for port_element in ports_element.findall("port"):
        port = _parse_port(port_element)
        if port is not None:
            ports.append(port)
    return ports


def _parse_port(element: ET.Element) -> Port | None:
    portid = _optional_int(element.get("portid"))
    if portid is None or not 0 <= portid <= 65535:
        return None

    state = element.find("state")
    return Port(
        portid=portid,
        protocol=element.get("protocol", ""),
        state=state.get("state", "unknown") if state is not None else "unknown",
        reason=state.get("reason", "") if state is not None else "",
        service=_parse_service(element.find("service")),
        scripts=_parse_scripts(element),
    )


def _parse_service(element: ET.Element | None) -> Service | None:
    if element is None:
        return None
    return Service(
        name=element.get("name", ""),
        product=element.get("product", ""),
        version=element.get("version", ""),
        extrainfo=element.get("extrainfo", ""),
        tunnel=element.get("tunnel", ""),
        method=element.get("method", ""),
        conf=element.get("conf", ""),
    )


def _parse_scripts(element: ET.Element, path: str = "script") -> list[Script]:
    return [
        Script(id=script.get("id", ""), output=script.get("output", ""))
        for script in element.findall(path)
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
                accuracy=_accuracy(match),
                os_classes=[
                    OSClass(
                        os_type=osclass.get("type", ""),
                        vendor=osclass.get("vendor", ""),
                        osfamily=osclass.get("osfamily", ""),
                        osgen=osclass.get("osgen", ""),
                        accuracy=_accuracy(osclass),
                    )
                    for osclass in match.findall("osclass")
                ],
            )
        )
    return matches


def _accuracy(element: ET.Element) -> int | None:
    value = _optional_int(element.get("accuracy"))
    return value if value is not None and 0 <= value <= 100 else None


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
    value = _optional_int(element.get(name)) if element is not None else None
    return value if value is not None else default


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
    if value is None or len(value) > 32:
        return None
    try:
        return int(value)
    except ValueError:
        return None
