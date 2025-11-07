"""Tests for the nmap XML parser."""

from __future__ import annotations

import textwrap

from nmap2report.parser import NmapParseError, parse_file, parse_string

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


def test_wrong_root_raises_clear_error() -> None:
    try:
        parse_string("<report><host/></report>")
    except NmapParseError as exc:
        assert "expected <nmaprun> root" in str(exc)
        assert "<report>" in str(exc)
    else:
        raise AssertionError("NmapParseError was not raised")
