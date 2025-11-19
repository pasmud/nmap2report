"""End-to-end tests: run the real CLI with local synthetic XML."""

import csv
import io
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "inventory.xml"


def cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "nmap2report", *args],
        cwd=ROOT, capture_output=True, check=False, timeout=10,
    )


def test_default_html_to_stdout() -> None:
    result = cli(FIXTURE, "--title", "Office & café")
    assert result.returncode == 0
    assert not result.stderr
    report = result.stdout.decode()
    assert report.startswith("<!doctype html>")
    assert "<h1>Office &amp; café</h1>" in report
    assert "#host-1" in report
    assert "web.example.test" in report
    assert "demo &lt;banner&gt;\nsecond line" in report
    assert "Example OS (90% reported match)" in report
    assert "Synthetic host observation" in report
    assert "<td>open|filtered</td>" in report
    assert '<span class="stat-value">1</span><span class="stat-label">Open ports</span>' in report


def test_markdown_to_output_file(tmp_path) -> None:
    destination = tmp_path / "report.md"
    result = cli(FIXTURE, "-f", "markdown", "-o", destination)
    assert result.returncode == 0
    assert not result.stdout and not result.stderr
    report = destination.read_text(encoding="utf-8")
    assert report.startswith("# nmap scan report\n")
    assert "- **Host entries:** 3\n" in report
    assert "- **Down:** 1\n" in report
    assert "- **Other / unknown:** 1\n" in report
    assert "| 53 | udp | open&#124;filtered |" in report
    assert "~~~\ndemo <banner>\nsecond line\n~~~" in report


def test_csv_machine_readable(tmp_path) -> None:
    destination = tmp_path / "report.csv"
    result = cli(FIXTURE, "-f", "csv", "-o", destination)
    assert result.returncode == 0
    assert not result.stdout and not result.stderr
    raw = destination.read_bytes()
    assert raw.count(b"\r\n") == 6
    rows = list(csv.DictReader(io.StringIO(raw.decode(), newline="")))
    assert [(r["host_index"], r["port"], r["state"]) for r in rows] == [
        ("1", "443", "open"), ("1", "8443", "filtered"), ("1", "53", "open|filtered"),
        ("2", "", ""), ("3", "", ""),
    ]
    assert rows[0]["service"] == "https (Example Web 1.0)"
    assert rows[0]["ipv6"] == "2001:db8::10"
    assert [row["host_status"] for row in rows[-2:]] == ["down", "unknown"]


@pytest.mark.parametrize("xml, message", [
    (None, b"No such file"),
    ("<nmaprun>", b"invalid XML"),
    ("<inventory/>", b"expected <nmaprun>"),
    ('<!DOCTYPE nmaprun SYSTEM "sample.dtd"><nmaprun/>', b"only a bare"),
])
def test_input_error_leaves_no_report(tmp_path, xml, message) -> None:
    source, destination = tmp_path / "input.xml", tmp_path / "report.html"
    if xml is not None:
        source.write_text(xml, encoding="utf-8")
    result = cli(source, "-o", destination)
    assert result.returncode == 1
    assert message in result.stderr and b"Traceback" not in result.stderr
    assert not result.stdout and not destination.exists()


def test_existing_output_is_never_overwritten(tmp_path) -> None:
    destination = tmp_path / "existing.html"
    destination.write_bytes(b"keep this")
    result = cli(FIXTURE, "-o", destination)
    assert result.returncode == 1
    assert b"File exists" in result.stderr
    assert destination.read_bytes() == b"keep this"


@pytest.mark.parametrize("options", [[], ["-f", "json"], ["-f", "csv", "--title", "Test"]])
def test_usage_errors(options) -> None:
    result = cli(*(options + [FIXTURE]) if options else [])
    assert result.returncode == 2
    assert b"usage:" in result.stderr
    assert not result.stdout
