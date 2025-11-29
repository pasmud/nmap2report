"""Offline command-line entry point."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from tempfile import TemporaryDirectory

from . import __version__
from .parser import NmapParseError, parse_file, parse_stream
from .report import ReportLimitError, render_csv, render_html, render_markdown


def _publish_report(destination: Path, report: str) -> None:
    """Publish a completely written report without replacing any existing path."""
    with TemporaryDirectory(dir=destination.parent, prefix=".nmap2report-") as staging:
        staged = Path(staging) / "report"
        with staged.open("x", encoding="utf-8", newline="") as stream:
            stream.write(report)
            stream.flush()
            os.fsync(stream.fileno())
        # Unlike rename, link fails if the destination appeared while writing.
        os.link(staged, destination)


def main(argv: Sequence[str] | None = None) -> int:
    """Convert XML from a local file or stdin; return an exit status."""
    parser = argparse.ArgumentParser(prog="nmap2report", description=__doc__)
    parser.add_argument("input", help="local nmap XML file, or - for stdin")
    parser.add_argument(
        "-f", "--format", choices=("html", "markdown", "csv"), default="html",
        help="report format (default: html)",
    )
    parser.add_argument("-o", "--output", type=Path, help="new output file (default: stdout)")
    parser.add_argument("--title", help="custom report title (HTML and Markdown only)")
    parser.add_argument(
        "--summary-only", action="store_true",
        help="show only aggregate counts (HTML and Markdown)",
    )
    parser.add_argument(
        "--omit-script-output", action="store_true",
        help="omit all host and port script entries (CSV already excludes them)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    if args.format == "csv" and args.title is not None:
        parser.error("--title is only available for HTML and Markdown")
    if args.format == "csv" and args.summary_only:
        parser.error("--summary-only is only available for HTML and Markdown")

    try:
        scan = parse_stream(sys.stdin.buffer) if args.input == "-" else parse_file(args.input)
        if args.format == "csv":
            report = render_csv(scan)
        else:
            render = render_html if args.format == "html" else render_markdown
            report = render(
                scan, args.title, summary_only=args.summary_only,
                omit_script_output=args.omit_script_output,
            )
        if args.output is None:
            sys.stdout.buffer.write(report.encode("utf-8"))
            sys.stdout.buffer.flush()
        else:
            _publish_report(args.output, report)
    except (NmapParseError, ReportLimitError, OSError, UnicodeError) as exc:
        # Keep untrusted XML names and paths from controlling the terminal.
        message = "".join(char if char.isprintable() else repr(char)[1:-1] for char in str(exc))
        print(f"nmap2report: {message}", file=sys.stderr)
        return 1
    return 0
