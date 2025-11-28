# nmap2report

Turn a saved Nmap XML file into a standalone HTML report, a GitHub-flavored
Markdown handoff, or a CSV inventory. The reports show what the file recorded:
host and port states, service labels, and, in the narrative formats, OS matches
and script output. No Nmap installation or network connection is required.

## Quickstart

With Python 3.11 or newer, run these commands from the repository root. The
included XML is entirely synthetic and uses reserved documentation addresses.
No installation is required to run from a checkout.

```sh
mkdir -p reports
python3 -m nmap2report tests/fixtures/inventory.xml -o reports/inventory.html
python3 -m nmap2report tests/fixtures/inventory.xml -f markdown --title "Lab inventory" -o reports/inventory.md
python3 -m nmap2report tests/fixtures/inventory.xml -f csv -o reports/inventory.csv
```

Open `reports/inventory.html` in a browser. The summary shows **3 host entries**
(1 up, 1 down, 1 unknown) and **1 open port**. The host detail shows TCP 443 as
`open`, TCP 8443 as `filtered`, and UDP 53 as `open|filtered`. The first CSV data
row looks like this:

```csv
"1","web.example.test","192.0.2.10","2001:db8::10","","up","443","tcp","open","syn-ack","https (Example Web 1.0)"
```

To install the `nmap2report` command locally without runtime dependencies:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/nmap2report --help
```

## Command reference

```text
nmap2report INPUT [-f {html,markdown,csv}] [-o OUTPUT] [--title TITLE] [--summary-only]
```

- `INPUT` is a local, regular Nmap XML file, or `-` to read one XML document
  from stdin (for example, `python3 -m nmap2report - < tests/fixtures/inventory.xml`).
  The same XML limits apply to both. To read a file literally named `-`, use `./-`.
- `--format` defaults to `html`. Format is never guessed from the output extension.
- `--output` writes a new UTF-8 file; an existing path is never overwritten. With
  no `--output`, the report is written to stdout as UTF-8.
- `--title` is optional for HTML and Markdown and is rejected for CSV.
- `--summary-only` keeps the title and the same aggregate counts in HTML or
  Markdown, but skips scan metadata, the host overview, and all host details.
  CSV remains a row-based inventory and does not accept this option.
- Exit codes: `0` for success, `1` for input, parsing, or output errors, and `2`
  for invalid command-line usage. Errors go to stderr. Invalid XML does not
  create an output file; a write failure can leave a partial file.

## Report coverage and limits

- Counts come from explicit `<host>` and `<port>` records, not from Nmap's run
  totals. Only the exact `open` state counts as open. Missing host/port states
  display as `unknown`; ports with missing or invalid IDs are skipped. Record
  order and duplicates are retained. Aggregate `<extraports>` counts, structured
  script children, and other unsupported XML fields are not exported.
- HTML and Markdown include host addresses, names, comments, explicit port
  rows, OS match labels, and host/port script output when present. HTML needs no
  external assets. Markdown uses GitHub-flavored tables and normalized inline
  whitespace. Services and OS labels are observations or estimates, not verified
  identifications or vulnerability verdicts. Reports may contain sensitive
  hostnames, recorded arguments, or script output; review before sharing.
- CSV contains one row per explicit port and one row with blank port fields per
  portless host. `host_index` is a 1-based index for the input file; the first
  recorded hostname and first address of each IPv4, IPv6, and MAC type are used.
  CSV fields are quoted, and formula-like text gets a leading apostrophe. This
  prefix is part of the exported value; leave spreadsheet columns as text when
  importing untrusted data. CSV output is limited to 32 Mi characters because
  it may repeat host details across rows.
- The XML root must be `<nmaprun>`. Input is limited to 16 MiB, 64 levels of XML
  nesting, and 100,000 elements, including ignored elements. Nmap's bare
  `<!DOCTYPE nmaprun>` is accepted; internal/external DTD subsets and custom
  entities are not processed. Stylesheets and inclusion directives are ignored.
  The converter does not execute scans, scripts, or recorded arguments.

## Development checks

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[dev]'
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/nmap2report --version
```

Tests use local synthetic XML and do not contact network services. CI verifies
Python 3.11 and 3.14 on pushes and pull requests. MIT licensed; see [LICENSE](LICENSE).

The November 2025 commit timeline is illustrative and is not evidence of
activity on those dates.
