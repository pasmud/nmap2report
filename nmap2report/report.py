"""Render parsed nmap scans as standalone HTML, Markdown, and CSV reports."""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final

from .models import Scan
from .risk import SEVERITY_ORDER, RiskAssessment, Severity, assess_scan

DEFAULT_TITLE: Final = "nmap scan report"

_CSS: Final = """
:root {
  color-scheme: light;
  --bg: #f5f7fa;
  --surface: #ffffff;
  --ink: #1d2733;
  --muted: #5f6f82;
  --line: #d9e0e8;
  --accent: #0b6e99;
  --critical: #9f1239;
  --high: #c2410c;
  --medium: #a16207;
  --low: #0369a1;
  --info: #475569;
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
.stat-label { color: var(--muted); font-size: .82rem; text-transform: uppercase; letter-spacing: .04em; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: .5rem .55rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .03em; }
tr:last-child td { border-bottom: 0; }
.severity { font-weight: 650; text-transform: capitalize; }
.severity-critical { color: var(--critical); }
.severity-high { color: var(--high); }
.severity-medium { color: var(--medium); }
.severity-low { color: var(--low); }
.severity-info { color: var(--info); }
.status { font-weight: 650; text-transform: capitalize; }
.status-up { color: #166534; }
.status-down { color: var(--critical); }
.empty { color: var(--muted); margin: 0; }
.page-footer { color: var(--muted); font-size: .85rem; }
@media print {
  body { background: #fff; padding: 0; }
  section { break-inside: avoid; border-color: #ccc; }
}
"""


@dataclass(frozen=True, slots=True)
class ReportSummary:
    """Aggregate counts used by every report format."""

    hosts_total: int
    hosts_up: int
    hosts_down: int
    open_ports: int
    severity_counts: dict[Severity, int]
    score: int

    @property
    def findings_total(self) -> int:
        """Total number of exposure findings."""
        return sum(self.severity_counts.values())


def summarize(scan: Scan, assessment: RiskAssessment | None = None) -> ReportSummary:
    """Build the shared summary for *scan*, reusing *assessment* when supplied."""
    risk = assessment if assessment is not None else assess_scan(scan)
    return ReportSummary(
        hosts_total=scan.host_count,
        hosts_up=scan.up_host_count,
        hosts_down=scan.down_host_count,
        open_ports=scan.open_port_count,
        severity_counts=risk.counts,
        score=risk.score,
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
        moment = datetime.fromtimestamp(epoch, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return str(epoch)
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def _scan_meta(scan: Scan) -> str:
    parts: list[str] = []
    if scan.version:
        parts.append(f"nmap {_escape(scan.version)}")
    if scan.args:
        parts.append(f"<code>{_escape(scan.args)}</code>")
    parts.append(f"started {_escape(_format_time(scan.start))}")
    return " &middot; ".join(parts)


def _stat(value: object, label: str) -> str:
    return (
        '<div class="stat">'
        f'<span class="stat-value">{_escape(value)}</span>'
        f'<span class="stat-label">{_escape(label)}</span>'
        "</div>"
    )


def _summary_section(summary: ReportSummary) -> str:
    stats = "".join(
        [
            _stat(summary.hosts_total, "hosts"),
            _stat(summary.hosts_up, "up"),
            _stat(summary.hosts_down, "down"),
            _stat(summary.open_ports, "open ports"),
            _stat(summary.findings_total, "findings"),
            _stat(summary.score, "heuristic score"),
        ]
    )
    severity_rows = "".join(
        f'<tr><td class="severity severity-{severity.value}">'
        f"{_escape(severity.value)}</td>"
        f"<td>{_escape(summary.severity_counts[severity])}</td></tr>"
        for severity in SEVERITY_ORDER
    )
    return (
        '<section class="summary" aria-labelledby="summary-heading">'
        '<h2 id="summary-heading">Summary</h2>'
        f'<div class="stats">{stats}</div>'
        '<table class="summary-table"><thead><tr><th>Severity</th><th>Findings</th>'
        f"</tr></thead><tbody>{severity_rows}</tbody></table>"
        "</section>"
    )


def _host_overview(scan: Scan) -> str:
    if not scan.hosts:
        return (
            '<section class="hosts"><h2>Hosts</h2>'
            '<p class="empty">No hosts were found in this scan.</p></section>'
        )

    rows = []
    for host in scan.hosts:
        addresses = ", ".join(address.addr for address in host.addresses)
        rows.append(
            "<tr>"
            f"<td>{_escape(host.display_name)}</td>"
            f'<td><span class="status status-{_escape(host.status)}">'
            f"{_escape(host.status)}</span></td>"
            f"<td>{_escape(addresses)}</td>"
            f"<td>{_escape(host.open_port_count)}</td>"
            "</tr>"
        )
    return (
        '<section class="hosts"><h2>Hosts</h2>'
        "<table><thead><tr><th>Host</th><th>Status</th><th>Addresses</th>"
        "<th>Open ports</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></section>"
    )


def render_html(scan: Scan, title: str | None = None) -> str:
    """Render a complete, self-contained HTML report for *scan*."""
    document_title = _clean_title(title)
    summary = summarize(scan)
    body = _summary_section(summary) + _host_overview(scan)
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_escape(document_title)}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n<body>\n"
        '<header class="page-header">\n'
        f"<h1>{_escape(document_title)}</h1>\n"
        f'<p class="meta">{_scan_meta(scan)}</p>\n'
        "</header>\n<main>\n"
        f"{body}\n"
        "</main>\n"
        '<footer class="page-footer"><p>Generated by nmap2report. '
        "Exposure levels are heuristics, not vulnerability findings.</p></footer>\n"
        "</body>\n</html>\n"
    )
