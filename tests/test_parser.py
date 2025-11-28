"""Tests for the nmap XML parser."""

from __future__ import annotations

import textwrap
from io import BytesIO

import pytest

from nmap2report import parser
from nmap2report.parser import NmapParseError, parse_file, parse_stream, parse_string

SAMPLE_XML = textwrap.dedent(
    """\
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE nmaprun>
    <nmaprun scanner="nmap" args="nmap -sV -O 192.0.2.0/24" start="1762000000"
             version="7.95" xmlversion="1.05">
      <scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
      <host starttime="1762000000" endtime="1762000025">
        <status state="up" reason="echo-reply" reason_ttl="64"/>
        <address addr="192.0.2.10" addrtype="ipv4"/>
        <address addr="2001:db8::10" addrtype="ipv6"/>
        <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Acme Networks"/>
        <hostnames>
          <hostname name="web01.example.test" type="PTR"/>
        </hostnames>
        <ports>
          <extraports state="closed" count="997"/>
          <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack" reason_ttl="64"/>
            <service name="ssh" product="OpenSSH" version="9.6p1"
                     extrainfo="Ubuntu Linux" method="probed" conf="10"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="nginx" version="1.24.0"
                     tunnel="ssl" method="probed" conf="10"/>
          </port>
          <port protocol="tcp" portid="443">
            <state state="closed" reason="reset"/>
          </port>
          <port protocol="tcp" portid="3389">
            <state state="filtered" reason="no-response"/>
            <service name="ms-wbt-server"/>
          </port>
        </ports>
        <os>
          <osmatch name="Linux 5.0 - 5.14" accuracy="98" line="12345">
            <osclass type="general purpose" vendor="Linux" osfamily="Linux"
                     osgen="5.X" accuracy="98"/>
          </osmatch>
        </os>
      </host>
      <host starttime="1762000000" endtime="1762000030">
        <status state="up" reason="echo-reply"/>
        <address addr="192.0.2.20" addrtype="ipv4"/>
        <hostnames>
          <hostname name="db01.example.test" type="PTR"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="3306">
            <state state="open" reason="syn-ack"/>
            <service name="mysql" product="MySQL" version="8.0.36" method="probed"/>
          </port>
          <port protocol="tcp" portid="6379">
            <state state="open" reason="syn-ack"/>
            <service name="redis" product="Redis key-value store" version="7.0.15"/>
            <script id="redis-info" output="redis_version:7.0.15&#10;connected_clients:1"/>
          </port>
        </ports>
        <script id="hostscript" output="OS: Linux 5.15"/>
      </host>
      <runstats>
        <finished time="1762000032" elapsed="32.75" exit="success"/>
        <hosts up="2" down="0" total="2"/>
      </runstats>
    </nmaprun>
    """
)


def test_parse_scan_metadata() -> None:
    scan = parse_string(SAMPLE_XML)
    assert scan.args == "nmap -sV -O 192.0.2.0/24"
    assert scan.start == 1762000000
    assert scan.version == "7.95"
    assert scan.xml_version == "1.05"
    assert len(scan.scan_info) == 1
    assert scan.scan_info[0].scan_type == "syn"
    assert scan.scan_info[0].num_services == 1000
    assert scan.runstats.hosts_up == 2
    assert scan.runstats.hosts_down == 0
    assert scan.runstats.hosts_total == 2
    assert scan.runstats.elapsed == 32.75
    assert scan.runstats.exit_status == "success"
    assert scan.runstats.finished_time == 1762000032


def test_parse_host_addresses_and_hostnames() -> None:
    host = parse_string(SAMPLE_XML).hosts[0]
    assert host.status == "up"
    assert host.starttime == 1762000000
    assert host.endtime == 1762000025
    assert host.ipv4 == "192.0.2.10"
    assert host.ipv6 == "2001:db8::10"
    assert host.mac == "00:11:22:33:44:55"
    assert [address.vendor for address in host.addresses] == [
        "",
        "",
        "Acme Networks",
    ]
    assert host.hostname == "web01.example.test"
    assert host.display_name == "web01.example.test"


def test_parse_port_states_and_services() -> None:
    host = parse_string(SAMPLE_XML).hosts[0]
    assert [(port.portid, port.protocol, port.state) for port in host.ports] == [
        (22, "tcp", "open"),
        (80, "tcp", "open"),
        (443, "tcp", "closed"),
        (3389, "tcp", "filtered"),
    ]
    assert host.open_port_count == 2
    ssh = host.ports[0]
    assert ssh.reason == "syn-ack"
    assert ssh.service is not None
    assert ssh.service.name == "ssh"
    assert ssh.service.product == "OpenSSH"
    assert ssh.service.version == "9.6p1"
    assert ssh.service.extrainfo == "Ubuntu Linux"
    assert ssh.service.method == "probed"
    assert ssh.service.conf == "10"
    assert host.ports[1].service is not None
    assert host.ports[1].service.tunnel == "ssl"
    assert host.ports[2].service is None
    assert host.ports[3].service_label == "ms-wbt-server"


def test_parse_file_reads_xml(tmp_path) -> None:
    scan_path = tmp_path / "scan.xml"
    scan_path.write_text(SAMPLE_XML, encoding="utf-8")
    scan = parse_file(scan_path)
    assert scan.host_count == 2
    assert scan.hosts[1].display_name == "db01.example.test"


def test_parse_stream_handles_short_reads_and_preserves_xml_encoding() -> None:
    class ShortReads(BytesIO):
        def read(self, size=-1):
            return super().read(min(size, 3))

    xml = '<?xml version="1.0" encoding="UTF-16"?><nmaprun args="été"/>'
    with ShortReads(xml.encode("utf-16")) as source:
        assert parse_stream(source).args == "été"
        assert not source.closed


def test_wrong_root_raises_clear_error() -> None:
    try:
        parse_string("<report><host/></report>")
    except NmapParseError as exc:
        assert "expected <nmaprun> root" in str(exc)
        assert "<report>" in str(exc)
    else:
        raise AssertionError("NmapParseError was not raised")


def test_parse_scripts_and_os_matches() -> None:
    scan = parse_string(SAMPLE_XML)
    web = scan.hosts[0]
    assert len(web.os_matches) == 1
    match = web.os_matches[0]
    assert match.name == "Linux 5.0 - 5.14"
    assert match.accuracy == 98
    assert len(match.os_classes) == 1
    assert match.os_classes[0].vendor == "Linux"
    assert match.os_classes[0].osfamily == "Linux"
    assert match.os_classes[0].osgen == "5.X"
    assert match.os_classes[0].accuracy == 98

    db = scan.hosts[1]
    assert [script.id for script in db.scripts] == ["hostscript"]
    assert db.scripts[0].output == "OS: Linux 5.15"
    assert [script.id for script in db.ports[1].scripts] == ["redis-info"]
    assert db.ports[1].scripts[0].output == (
        "redis_version:7.0.15\nconnected_clients:1"
    )


def test_missing_optional_sections_use_defaults() -> None:
    scan = parse_string(
        "<nmaprun><host><address addr='192.0.2.1' addrtype='ipv4'/></host></nmaprun>"
    )
    assert scan.args == ""
    assert scan.start is None
    assert scan.scan_info == []
    assert scan.runstats.hosts_total == 0
    assert scan.runstats.elapsed == 0.0
    host = scan.hosts[0]
    assert host.status == "unknown"
    assert host.ports == []
    assert host.scripts == []
    assert host.os_matches == []
    assert host.display_name == "192.0.2.1"


def test_malformed_numeric_attributes_fall_back() -> None:
    scan = parse_string(
        """<nmaprun start="not-a-number">
        <host><status state="up"/>
          <ports>
            <port protocol="tcp" portid="abc"><state state="open"/></port>
            <port protocol="tcp" portid="8080"><state state="open"/></port>
          </ports>
          <os><osmatch name="Unknown" accuracy="high"/></os>
        </host>
        <runstats><finished elapsed="oops"/><hosts up="x" down="2" total="3"/></runstats>
        </nmaprun>"""
    )
    assert scan.start is None
    assert [port.portid for port in scan.hosts[0].ports] == [8080]
    assert scan.hosts[0].os_matches[0].accuracy is None
    assert scan.runstats.hosts_up == 0
    assert scan.runstats.hosts_down == 2
    assert scan.runstats.elapsed == 0.0


def test_invalid_xml_raises_nmap_parse_error() -> None:
    with pytest.raises(NmapParseError, match="invalid XML"):
        parse_string("<nmaprun><host></nmaprun>")


def test_empty_addresses_and_scripts_are_skipped() -> None:
    scan = parse_string(
        """<nmaprun><host>
        <address addrtype="ipv4"/>
        <script output="no id"/>
        </host></nmaprun>"""
    )
    assert scan.hosts[0].addresses == []
    assert scan.hosts[0].scripts == []


def test_missing_file_raises_oserror(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        parse_file(tmp_path / "absent.xml")


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
@pytest.mark.parametrize("declaration", [
    '<!DOCTYPE nmaprun SYSTEM "sample.dtd">',
    '<!DOCTYPE nmaprun [<!ENTITY example "synthetic text">]>',
    '<!DOCTYPE nmaprun []>',
])
def test_dtds_with_subsets_are_rejected(declaration, encoding) -> None:
    with pytest.raises(NmapParseError, match="only a bare"):
        parse_string(f"{declaration}<nmaprun/>".encode(encoding))


def test_standard_entities_and_local_xml_encoding() -> None:
    xml = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE nmaprun>'
    xml += '<nmaprun args="été &amp; demo &#x3C;"/>'
    assert parse_string(xml.encode("utf-16")).args == "été & demo <"
    assert parse_string(xml).args == "été & demo <"


def test_inclusion_directives_and_stylesheet_are_ignored() -> None:
    scan = parse_string(
        '<?xml-stylesheet href="sample.xsl"?><nmaprun>'
        '<include xmlns="http://www.w3.org/2001/XInclude" href="sample.xml"/>'
        '<host xmlns="urn:synthetic"/></nmaprun>'
    )
    assert scan.hosts == []


def test_invalid_encoding_is_a_parse_error() -> None:
    with pytest.raises(NmapParseError, match="invalid XML"):
        parse_string(b'<?xml version="1.0" encoding="UNKNOWN-ENCODING"?><nmaprun/>')


def test_xml_byte_limit_applies_to_text_files_and_streams(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(parser, "MAX_XML_BYTES", 24)
    exact = '<nmaprun args="éé"/>'
    exact += " " * (24 - len(exact.encode()))
    source = tmp_path / "input.xml"
    source.write_bytes(exact.encode())
    assert parse_file(source).args == "éé"
    assert parse_stream(BytesIO(exact.encode())).args == "éé"
    with pytest.raises(NmapParseError, match="24-byte limit"):
        parse_string(exact + "é")
    source.write_bytes((exact + " ").encode())
    with pytest.raises(NmapParseError, match="24-byte limit"):
        parse_file(source)
    with BytesIO(source.read_bytes() + b"unread") as stream:
        with pytest.raises(NmapParseError, match="24-byte limit"):
            parse_stream(stream)
        assert stream.read() == b"unread"


def test_tree_depth_limit(monkeypatch) -> None:
    monkeypatch.setattr(parser, "MAX_XML_DEPTH", 3)
    assert parse_string("<nmaprun><host><ports/></host></nmaprun>").host_count == 1
    with pytest.raises(NmapParseError, match="3-level nesting limit"):
        parse_string("<nmaprun><host><ports><port/></ports></host></nmaprun>")


def test_element_limit_counts_ignored_elements(monkeypatch) -> None:
    monkeypatch.setattr(parser, "MAX_XML_ELEMENTS", 3)
    assert parse_string("<nmaprun><ignored/><host/></nmaprun>").host_count == 1
    with pytest.raises(NmapParseError, match="3-element limit"):
        parse_string("<nmaprun><ignored/><ignored/><host/></nmaprun>")


def test_ports_outside_valid_range_are_skipped() -> None:
    entries = "".join(f'<port portid="{value}"/>' for value in (-1, 0, 65535, 65536))
    host = parse_string(f"<nmaprun><host><ports>{entries}</ports></host></nmaprun>").hosts[0]
    assert [port.portid for port in host.ports] == [0, 65535]
