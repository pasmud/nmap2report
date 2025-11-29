"""End-to-end tests: run the real CLI with local synthetic XML."""

import csv
import errno
import io
import subprocess
import sys
from pathlib import Path

import pytest

from nmap2report import cli as cli_module

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "inventory.xml"


def cli(*args, input_bytes=None):
    return subprocess.run(
        [sys.executable, "-m", "nmap2report", *args],
        cwd=ROOT, input=input_bytes, capture_output=True, check=False, timeout=10,
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


def test_stdin_matches_file_input() -> None:
    result = cli("-", input_bytes=FIXTURE.read_bytes())
    assert result.returncode == 0
    assert not result.stderr
    assert result.stdout == cli(FIXTURE).stdout


@pytest.mark.parametrize("data, message", [
    (b"", b"invalid XML"),
    (b"<!DOCTYPE nmaprun []><nmaprun/>", b"only a bare"),
    (b"<nmaprun>" + b"<nested>" * 64, b"nesting limit"),
    (b"<nmaprun>" + b"<entry/>" * 100_000, b"element limit"),
])
def test_stdin_rejects_invalid_xml_without_creating_output(tmp_path, data, message) -> None:
    destination = tmp_path / "report.html"
    result = cli("-", "-o", destination, input_bytes=data)
    assert result.returncode == 1
    assert message in result.stderr
    assert not result.stdout and not destination.exists()


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


@pytest.mark.parametrize("fmt", ["html", "markdown"])
def test_summary_only_keeps_counts_and_omits_details(fmt) -> None:
    data = FIXTURE.read_bytes().replace(b'<nmaprun scanner=', b'<nmaprun args="demo args" scanner=')
    result = cli("-", "-f", fmt, "--summary-only", "--title", "Inventory counts", input_bytes=data)
    assert result.returncode == 0
    assert not result.stderr
    document = result.stdout.decode()
    assert "Inventory counts" in document
    for label, count in [("Host entries", 3), ("Up", 1), ("Down", 1),
                         ("Other / unknown", 1), ("Open ports", 1)]:
        if fmt == "html":
            assert f'>{count}</span><span class="stat-label">{label}</span>' in document
        else:
            assert f"- **{label}:** {count}\n" in document
    for detail in ("demo args", "web.example", "192.0.2.10", "8443", "sample-banner", "Example OS"):
        assert detail not in document


@pytest.mark.parametrize("fmt", ["html", "markdown", "csv"])
def test_omit_script_output_for_sharing(fmt) -> None:
    baseline = cli(FIXTURE, "-f", fmt)
    shared = cli(FIXTURE, "-f", fmt, "--omit-script-output")
    assert baseline.returncode == shared.returncode == 0
    assert not shared.stderr
    dash = b"&#45;" if fmt == "markdown" else b"-"
    markers = (
        b"sample" + dash + b"banner", b"second line",
        b"sample" + dash + b"note", b"Synthetic host observation",
    )
    assert all(marker not in shared.stdout for marker in markers)
    assert b"Example Web 1" in shared.stdout
    if fmt == "csv":
        assert shared.stdout == baseline.stdout
    else:
        assert all(marker in baseline.stdout for marker in markers)
        assert b"Example OS" in shared.stdout
        assert b"Open ports" in shared.stdout


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
    assert list(tmp_path.iterdir()) == [destination]


def test_dangling_output_symlink_is_not_followed_or_replaced(tmp_path) -> None:
    destination, target = tmp_path / "report.html", tmp_path / "missing.html"
    destination.symlink_to(target)
    result = cli(FIXTURE, "-o", destination)
    assert result.returncode == 1
    assert destination.readlink() == target
    assert not target.exists()
    assert list(tmp_path.iterdir()) == [destination]


def test_failed_file_sync_never_publishes_output(tmp_path, monkeypatch, capsys) -> None:
    destination = tmp_path / "report.html"

    def fail_sync(_fd):
        assert not destination.exists()
        raise OSError(errno.ENOSPC, "simulated disk full")

    monkeypatch.setattr(cli_module.os, "fsync", fail_sync)
    assert cli_module.main([str(FIXTURE), "-o", str(destination)]) == 1
    captured = capsys.readouterr()
    assert "simulated disk full" in captured.err
    assert not captured.out and not list(tmp_path.iterdir())


def test_output_created_during_publication_is_preserved(tmp_path, monkeypatch, capsys) -> None:
    destination = tmp_path / "report.html"
    real_link = cli_module.os.link

    def create_competing_output(staged, path):
        assert path == destination and not path.exists()
        assert staged.read_bytes().endswith(b"</body>\n</html>\n")
        path.write_bytes(b"another writer's report")
        return real_link(staged, path)

    monkeypatch.setattr(cli_module.os, "link", create_competing_output)
    assert cli_module.main([str(FIXTURE), "-o", str(destination)]) == 1
    assert "File exists" in capsys.readouterr().err
    assert destination.read_bytes() == b"another writer's report"
    assert list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize("options", [
    [], ["-f", "json"], ["-f", "csv", "--title", "Test"], ["-f", "csv", "--summary-only"],
])
def test_usage_errors(options) -> None:
    result = cli(*(options + [FIXTURE]) if options else [])
    assert result.returncode == 2
    assert b"usage:" in result.stderr
    assert not result.stdout
