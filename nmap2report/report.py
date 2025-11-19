"""Render parsed nmap scans as standalone HTML, Markdown, and CSV reports."""

from __future__ import annotations

import csv
import html
import io
import re
import string
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from .models import Host, Port, Scan, Script

DEFAULT_TITLE: Final = "nmap scan report"
MAX_CSV_CHARS: Final = 32 * 1024 * 1024
_PORT_COLUMNS = ("Port", "Protocol", "State", "Reason", "Service")
_MD_ENTITIES = str.maketrans({char: f"&#{ord(char)};" for char in string.punctuation})
_REPORT_NOTE = (
    "This report reflects recorded scan data only. Service and OS labels may be estimates."
)

_CSS: Final = """
:root {
  color-scheme: light;
  --bg: #f5f7fa;
  --surface: #ffffff;
  --ink: #1d2733;
  --muted: #5f6f82;
  --line: #d9e0e8;
  --accent: #0b6e99;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 2rem 1.25rem 3rem;
  background: var(--bg);
  color: var(--ink);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main, .page-header, .page-footer { max-width: 1100px; margin: 0 auto; }
.page-header h1 { margin: 0 0 .35rem; font-size: 1.85rem; }
.meta { margin: 0 0 1.5rem; color: var(--muted); }
.meta code {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: .1rem .35rem;
}
section {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 1.25rem;
  margin-bottom: 1.25rem;
}
h2 { margin: 0 0 .9rem; font-size: 1.2rem; }
.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: .75rem;
  margin-bottom: 1rem;
}
.stat {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: .7rem .8rem;
}
.stat-value { display: block; font-size: 1.5rem; font-weight: 650; }
.stat-label {
  color: var(--muted); font-size: .82rem; text-transform: uppercase; letter-spacing: .04em;
}
table { width: 100%; border-collapse: collapse; overflow-wrap: anywhere; }
th, td {
  text-align: left; padding: .5rem .55rem; border-bottom: 1px solid var(--line);
  vertical-align: top;
}
th { color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .03em; }
tr:last-child td { border-bottom: 0; }
.status { font-weight: 650; }
.status-up { color: #166534; }
.status-down { color: #9f1239; }
.empty { color: var(--muted); margin: 0; }
a { color: var(--accent); }
.meta, .host { overflow-wrap: anywhere; }
.host-header { display: flex; flex-wrap: wrap; align-items: baseline; gap: .75rem; }
.host-header h2 { margin: 0; }
.host-meta { color: var(--muted); margin: .35rem 0 1rem; }
.host-meta strong { color: var(--ink); font-weight: 600; }
h3 { margin: 1.25rem 0 .6rem; font-size: 1rem; }
.script { margin: .5rem 0; border: 1px solid var(--line); border-radius: 6px; }
.script summary { cursor: pointer; padding: .45rem .6rem; color: var(--muted); }
pre {
  margin: 0;
  padding: .75rem;
  overflow-x: auto;
  background: #f8fafc;
  border-top: 1px solid var(--line);
  font: 12.5px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.os-list { margin: 0; padding-left: 1.2rem; }
.page-footer { color: var(--muted); font-size: .85rem; }
@media print {
  body { background: #fff; padding: 0; }
  section { break-inside: avoid; border-color: #ccc; }
}
"""


@dataclass(frozen=True, slots=True)
class ReportSummary:
    """Counts derived from explicit host and port entries."""

    hosts_total: int
    hosts_up: int
    hosts_down: int
    open_ports: int
    hosts_other: int


def summarize(scan: Scan) -> ReportSummary:
    """Summarize recorded entries without interpreting script or service data."""
    up, down = scan.up_host_count, scan.down_host_count
    return ReportSummary(
        hosts_total=scan.host_count,
        hosts_up=up,
        hosts_down=down,
        open_ports=scan.open_port_count,
        hosts_other=scan.host_count - up - down,
    )


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _clean_title(title: str | None) -> str:
    if title is None:
        return DEFAULT_TITLE
    cleaned = " ".join(title.split())
    return cleaned or DEFAULT_TITLE


def _format_time(epoch: int | None) -> str:
    if epoch is None:
        return "unknown"
    try:
        moment = datetime.fromtimestamp(epoch, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return str(epoch)
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def _scan_meta(scan: Scan) -> list[tuple[str, str]]:
    parts = [("Started", _format_time(scan.start))]
    if scan.version:
        parts.append(("nmap version", scan.version))
    if scan.runstats.finished_time is not None:
        parts.append(("Finished", _format_time(scan.runstats.finished_time)))
    if scan.runstats.exit_status:
        parts.append(("Recorded exit status", scan.runstats.exit_status))
    if scan.args:
        parts.append(("Recorded arguments", scan.args))
    return parts


def _summary_items(summary: ReportSummary) -> tuple[tuple[str, int], ...]:
    return (
        ("Host entries", summary.hosts_total),
        ("Up", summary.hosts_up),
        ("Down", summary.hosts_down),
        ("Other / unknown", summary.hosts_other),
        ("Open ports", summary.open_ports),
    )


def _stat(value: object, label: str) -> str:
    return (
        '<div class="stat">'
        f'<span class="stat-value">{_escape(value)}</span>'
        f'<span class="stat-label">{_escape(label)}</span>'
        "</div>"
    )


def _summary_section(summary: ReportSummary) -> str:
    stats = "".join(_stat(value, label) for label, value in _summary_items(summary))
    return (
        '<section class="summary" aria-labelledby="summary-heading">'
        '<h2 id="summary-heading">Summary</h2>'
        f'<div class="stats">{stats}</div>'
        "</section>"
    )


def _status(host: Host) -> str:
    css = f"status-{host.status}" if host.status in {"up", "down"} else "status-other"
    return f'<span class="status {css}">{_escape(host.status)}</span>'


def _host_overview(scan: Scan) -> str:
    if not scan.hosts:
        return (
            '<section class="hosts"><h2>Hosts</h2>'
            '<p class="empty">No host entries were recorded.</p></section>'
        )

    rows = []
    for index, host in enumerate(scan.hosts, 1):
        rows.append(
            "<tr>"
            f'<td><a href="#host-{index}">{_escape(host.display_name)}</a></td>'
            f"<td>{_status(host)}</td>"
            f"<td>{_escape(host.open_port_count)}</td>"
            "</tr>"
        )
    return (
        '<section class="hosts"><h2>Hosts</h2>'
        "<table><thead><tr><th>Host</th><th>Status</th>"
        "<th>Open ports</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></section>"
    )


def _host_meta(host: Host) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = []
    if host.addresses:
        addresses = [
            " ".join(part for part in (a.addr, a.addrtype, a.vendor) if part)
            for a in host.addresses
        ]
        fields.append(("Addresses", ", ".join(addresses)))
    if host.hostnames:
        fields.append(("Names", ", ".join(name.name for name in host.hostnames)))
    if host.comment:
        fields.append(("Comment", host.comment))
    return fields


def _port_values(port: Port) -> tuple[object, ...]:
    return (port.portid, port.protocol, port.state, port.reason, port.service_label)


def _html_script(script: Script) -> str:
    return (
        f'<details class="script"><summary>{_escape(script.id)}</summary>'
        f"<pre>{_escape(script.output)}</pre></details>"
    )


def _os_labels(host: Host) -> list[str]:
    return [
        f"{match.name} ({match.accuracy}% reported match)"
        if match.accuracy is not None else match.name
        for match in host.os_matches
    ]


def _html_host(index: int, host: Host) -> str:
    details = "".join(
        f'<p class="host-meta"><strong>{label}:</strong> {_escape(value)}</p>'
        for label, value in _host_meta(host)
    )
    ports = '<p class="empty">No explicit port entries were recorded.</p>'
    if host.ports:
        headings = "".join(f'<th scope="col">{label}</th>' for label in _PORT_COLUMNS)
        rows = []
        for port in host.ports:
            cells = "".join(f"<td>{_escape(value)}</td>" for value in _port_values(port))
            rows.append(f"<tr>{cells}</tr>")
            if port.scripts:
                scripts = "".join(_html_script(script) for script in port.scripts)
                rows.append(f'<tr><td colspan="5">{scripts}</td></tr>')
        ports = f"<table><thead><tr>{headings}</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    os_items = "".join(f"<li>{_escape(label)}</li>" for label in _os_labels(host))
    os_section = f'<h3>OS matches</h3><ul class="os-list">{os_items}</ul>' if os_items else ""
    host_scripts = ""
    if host.scripts:
        host_scripts = "<h3>Host scripts</h3>" + "".join(map(_html_script, host.scripts))
    return (
        f'<section class="host" id="host-{index}">'
        f'<div class="host-header"><h2>{_escape(host.display_name)}</h2>{_status(host)}</div>'
        f"{details}<h3>Ports</h3>{ports}{os_section}{host_scripts}</section>"
    )


def render_html(scan: Scan, title: str | None = None) -> str:
    """Render a complete, self-contained HTML report for *scan*."""
    document_title = _clean_title(title)
    summary = summarize(scan)
    body = _summary_section(summary) + _host_overview(scan)
    body += "\n".join(_html_host(index, host) for index, host in enumerate(scan.hosts, 1))
    meta = " &middot; ".join(
        f"{label}: <code>{_escape(value)}</code>" for label, value in _scan_meta(scan)
    )
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'">\n'
        f"<title>{_escape(document_title)}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n<body>\n"
        '<header class="page-header">\n'
        f"<h1>{_escape(document_title)}</h1>\n"
        f'<p class="meta">{meta}</p>\n'
        "</header>\n<main>\n"
        f"{body}\n"
        "</main>\n"
        f'<footer class="page-footer"><p>{_REPORT_NOTE}</p></footer>\n'
        "</body>\n</html>\n"
    )


def _md(value: object) -> str:
    # Entities display as literal text without introducing GFM syntax or autolinks.
    return " ".join(str(value).split()).translate(_MD_ENTITIES)


def _md_script(script: Script, context: str) -> str:
    output = script.output.replace("\r\n", "\n").replace("\r", "\n")
    longest = max((len(run[0]) for run in re.finditer(r"~+", output)), default=0)
    fence = "~" * max(3, longest + 1)
    return f"**{context}:** {_md(script.id)}\n\n{fence}\n{output}\n{fence}\n"


def render_markdown(scan: Scan, title: str | None = None) -> str:
    """Render a GitHub-flavored Markdown report with untrusted data as text."""
    lines = [f"# {_md(_clean_title(title))}", ""]
    lines.extend(f"- **{label}:** {_md(value)}" for label, value in _scan_meta(scan))
    lines.extend(("", "## Summary", ""))
    lines.extend(f"- **{label}:** {value}" for label, value in _summary_items(summarize(scan)))
    if not scan.hosts:
        lines.extend(("", "No host entries were recorded."))
    for host in scan.hosts:
        lines.extend(("", f"## {_md(host.display_name)}", "", f"- **Status:** {_md(host.status)}"))
        lines.extend(f"- **{label}:** {_md(value)}" for label, value in _host_meta(host))
        lines.extend(("", "### Ports", ""))
        if host.ports:
            lines.append("| " + " | ".join(_PORT_COLUMNS) + " |")
            lines.append("| " + " | ".join("---" for _ in _PORT_COLUMNS) + " |")
            for port in host.ports:
                lines.append("| " + " | ".join(map(_md, _port_values(port))) + " |")
            for port in host.ports:
                for script in port.scripts:
                    context = f"Port {port.portid} ({_md(port.protocol)}) script"
                    lines.extend(("", _md_script(script, context)))
        else:
            lines.append("No explicit port entries were recorded.")
        if host.os_matches:
            lines.extend(("", "### OS matches", ""))
            lines.extend(f"- {_md(label)}" for label in _os_labels(host))
        if host.scripts:
            lines.extend(("", "### Host scripts", ""))
            lines.extend(_md_script(script, "Host script") for script in host.scripts)
    lines.extend(("", _REPORT_NOTE, ""))
    return "\n".join(lines)


class ReportLimitError(ValueError):
    """Raised when an export exceeds its size limit."""


def _csv_text(value: object) -> str:
    text = str(value)
    for char in text:
        if char in "\t\n\r":
            return "'" + text
        if not (char.isspace() or unicodedata.category(char) in {"Cc", "Cf"}):
            if unicodedata.normalize("NFKC", char) in "=+-@":
                return "'" + text
            break
    return text


def render_csv(scan: Scan) -> str:
    """Render one row per explicit port, plus a row for each portless host."""
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, quoting=csv.QUOTE_ALL)
    writer.writerow((
        "host_index", "hostname", "ipv4", "ipv6", "mac", "host_status",
        "port", "protocol", "state", "reason", "service",
    ))
    for index, host in enumerate(scan.hosts, 1):
        identifiers = tuple(map(_csv_text, (
            index, host.hostname, host.ipv4, host.ipv6, host.mac, host.status,
        )))
        for port in host.ports or [None]:
            values = _port_values(port) if port is not None else ("",) * len(_PORT_COLUMNS)
            writer.writerow((*identifiers, *map(_csv_text, values)))
            if stream.tell() > MAX_CSV_CHARS:
                raise ReportLimitError(f"CSV exceeds the {MAX_CSV_CHARS:,}-character limit")
    return stream.getvalue()
