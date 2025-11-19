"""Support running directly from a checkout with python -m nmap2report."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
