"""Exercise escaping and format-specific report boundaries."""

import csv
import io
import json
from html.parser import HTMLParser

import pytest

from nmap2report import report
from nmap2report.models import Address, Host, Hostname, Port, Scan, Script, Service
from nmap2report.parser import parse_string


def test_html_treats_all_recorded_markup_as_text() -> None:
    markup = '<img src="example.test/logo"> & <script>example</script>'
    scan = Scan(args=markup, hosts=[Host(
        hostnames=[Hostname(markup)], status=markup, comment=markup,
        ports=[Port(portid=80, protocol=markup, state=markup, reason=markup,
                    service=Service(name=markup), scripts=[Script(markup, markup)])],
    )])
    document = report.render_html(scan, title=markup)
    tags = set()
    data = []

    class AuditParser(HTMLParser):
        def handle_starttag(self, tag, attrs):
            tags.add(tag)

        def handle_data(self, text):
            data.append(text)

    AuditParser().feed(document)
    assert {"img", "script"}.isdisjoint(tags)
    assert "Content-Security-Policy" in document
    assert data.count(markup) >= 10


def test_markdown_entities_and_script_fence() -> None:
    scan = Scan(hosts=[Host(
        ports=[Port(1, "tcp", "open|filtered", "entry\n|broken")],
        scripts=[Script("[script]", "line 1\r~~~\r\n<script>text</script>\n~~~~\nline 5")],
    )])
    document = report.render_markdown(scan, "[example](https://example.test)\n# New title")
    assert document.splitlines()[0] == (
        "# &#91;example&#93;&#40;https&#58;&#47;&#47;example&#46;test&#41; &#35; New title"
    )
    assert "| 1 | tcp | open&#124;filtered | entry &#124;broken | unknown |" in document
    assert "**Host script:** &#91;script&#93;" in document
    assert "~~~~~\nline 1\n~~~\n<script>text</script>\n~~~~\nline 5\n~~~~~" in document


@pytest.mark.parametrize("text", [
    "=1+1", "+42", "-42", "@example", "  =example", "\ttext", "\rtext", "\ntext",
    "\ufeff=example", "\u00a0＠example", '="quoted, field"',
])
def test_csv_neutralizes_formula_prefixes_in_recorded_fields(text) -> None:
    scan = Scan(hosts=[Host(
        status=text, hostnames=[Hostname(text)], addresses=[Address(text, "ipv4")],
        ports=[Port(1, text, text, text, Service(name=text))],
    )])
    row = next(csv.DictReader(io.StringIO(report.render_csv(scan), newline="")))
    assert row["port"] == "1"
    assert all(row[key] == "'" + text for key in (
        "hostname", "ipv4", "host_status", "protocol", "state", "reason", "service",
    ))


def test_csv_preserves_non_formula_fields_and_structural_quoting() -> None:
    comment = 'Recorded "value", with comma\nand newline'
    scan = Scan(hosts=[Host(ports=[Port(65535, "tcp", "open", reason=comment)])])
    row = next(csv.DictReader(io.StringIO(report.render_csv(scan), newline="")))
    assert row["reason"] == comment
    assert row["port"] == "65535"


def test_csv_rejects_oversized_output(monkeypatch) -> None:
    monkeypatch.setattr(report, "MAX_CSV_CHARS", 160)
    scan = Scan(hosts=[Host(hostnames=[Hostname("x" * 80)], ports=[Port(80, "tcp", "open")])])
    with pytest.raises(report.ReportLimitError, match="160-character limit"):
        report.render_csv(scan)


def test_empty_scan_is_explicit_in_each_format() -> None:
    scan = parse_string("<nmaprun/>")
    assert "No host entries were recorded." in report.render_html(scan)
    assert "No host entries were recorded." in report.render_markdown(scan)
    assert list(csv.DictReader(io.StringIO(report.render_csv(scan), newline=""))) == []
    assert json.loads(report.render_json_summary(scan)) == {
        "hosts_total": 0, "hosts_up": 0, "hosts_down": 0, "hosts_other": 0, "open_ports": 0,
    }


def test_json_summary_counts_explicit_entries_instead_of_run_totals() -> None:
    scan = parse_string("""<nmaprun>
      <host><status state="unrecognized"/><ports>
        <extraports state="open" count="500"/>
        <port portid="bad"><state state="open"/></port>
        <port portid="443"><state state="open"/></port>
        <port portid="443"><state state="open"/></port>
        <port portid="8443"><state state="open|filtered"/></port>
      </ports></host>
      <runstats><hosts total="800" up="700" down="100"/></runstats>
    </nmaprun>""")
    assert json.loads(report.render_json_summary(scan)) == {
        "hosts_total": 1, "hosts_up": 0, "hosts_down": 0, "hosts_other": 1, "open_ports": 2,
    }
