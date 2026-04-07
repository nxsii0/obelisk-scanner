from __future__ import annotations

import argparse


HELP_EPILOG = """
----------------------------------------------------
  EXAMPLES
----------------------------------------------------

  Scan a requirements.txt:
    python -m obeliskscan scan -f requirements.txt

  Scan a project directory:
    python -m obeliskscan scan -d ./myproject

  Scan a specific package inline:
    python -m obeliskscan scan --package requests==2.27.0

  Scan a live target (URL/IP) for CVEs via HTTP/port fingerprinting:
    python -m obeliskscan scan --target scanme.nmap.org
    python -m obeliskscan scan --target https://example.com --target-ports 80,443,22
----------------------------------------------------
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="obeliskscan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP_EPILOG,
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="Scan packages/targets for CVEs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP_EPILOG,
    )

    source = scan.add_mutually_exclusive_group()
    source.add_argument("-f", "--file", metavar="FILE")
    source.add_argument("-d", "--dir", metavar="DIR")
    source.add_argument("--package", metavar="PKG")
    source.add_argument("--target", metavar="URL/IP")

    scan.add_argument(
        "--target-ports",
        default="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8000,8080,8443",
        metavar="PORTS",
    )
    scan.add_argument("--severity", default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"])
    scan.add_argument("--ignore", default="", metavar="CVE_IDS")
    scan.add_argument("--cve", default=None, metavar="CVE_ID")
    scan.add_argument("--limit", type=int, default=None, metavar="N")
    scan.add_argument(
        "--format",
        default=None,
        metavar="FMT",
        help="Export formats (comma-separated: html,pdf,json,csv). If omitted, you will be prompted.",
    )
    scan.add_argument("--output-dir", default="results", metavar="DIR")
    scan.add_argument("--timeout", type=int, default=10, metavar="SEC")
    scan.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification (not recommended).")
    scan.add_argument("--no-color", action="store_true")
    scan.add_argument("--verbose", action="store_true")
    scan.add_argument("--ci", action="store_true")
    scan.add_argument("--no-export", action="store_true")

    return parser

