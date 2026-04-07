from __future__ import annotations

import re
import sys
import io
from typing import Any

try:
    from rich.align import Align  # type: ignore
    from rich.box import HEAVY, MINIMAL  # type: ignore
    from rich.columns import Columns  # type: ignore
    from rich.console import Console, Group  # type: ignore
    from rich.panel import Panel  # type: ignore
    from rich.table import Table  # type: ignore
    from rich.text import Text  # type: ignore

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from obeliskscan.domain.severity import SEVERITY_ORDER, SEVERITY_WEIGHTS


def strip_rich_tags(s: str) -> str:
    return re.sub(r"\[/?[a-z_ ]+\]", "", s)


def print_banner(no_color: bool = False):
    """Prints a robust, centered, glowing monolith logo."""
    if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
        try:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        except:
            pass

    raw_lines = [
        r"◢■■■◣",                                  
        r"█▌█▐█   ▄▀▀▄ █▀▀▄ █▀▀▀ █    █ ▄▀▀▀ █ ▄▀",
        r"█▌█▐█   █  █ █▀▀▄ █▀▀  █    █ ▀▀▀█ █▀▄",
        r"◥■■■◤   ▀▀▀  ▀▀▀  ▀▀▀▀ ▀▀▀▀ ▀ ▀▀▀  ▀  ▀",
    ]

    if no_color or not RICH_AVAILABLE:
        for line in raw_lines:
            print("    " + line)
        print("\n            S  C  A  N  N  E  R")
        print("   CVE Dependency & Target Scanner · OSV + NVD\n")
        return

    c = Console()
    
    # Calculate max width for solid centering as a single block
    max_w = max(len(l) for l in raw_lines)
    logo_block = Text("\n".join(l.ljust(max_w) for l in raw_lines), style="bold #bf00ff")

    content = Group(
        Align.center(logo_block),
        Text(""),
        Align.center(Text("S  C  A  N  N  E  R", style="bold #df80ff")),
        Text(""),
        Align.center(Text("CVE Dependency & Target Scanner · OSV + NVD", style="dim #bf00ff")),
    )

    c.print("\n")
    c.print(Align.center(content))
    c.print("\n")


class Printer:
    def __init__(self, *, no_color: bool = False):
        self.no_color = no_color
        self._console: Any = None

    def console(self):
        if self._console is None and RICH_AVAILABLE and not self.no_color:
            self._console = Console()
        return self._console

    def print(self, msg: str = "", **kwargs):
        c = self.console()
        if c:
            c.print(msg, **kwargs)
        else:
            print(strip_rich_tags(msg))


def print_clean_package(pr: Printer, pkg: dict):
    name = pkg["name"]
    version = pkg.get("version", "?")
    if pr.no_color or not RICH_AVAILABLE:
        print(f"  [OK] {name} ({version})")
    else:
        pr.print(f"  [green]OK  {name}[/green]  [dim]v{version} — Clean[/dim]")


def print_findings_table(pr: Printer, pkg: dict, cves: list[dict], *, limit: int | None = None):
    name = pkg["name"]
    version = pkg.get("version", "?")
    shown = cves
    truncated = 0
    if limit and len(cves) > limit:
        truncated = len(cves) - limit
        shown = cves[:limit]

    if pr.no_color or not RICH_AVAILABLE:
        print(f"\n{'='*70}")
        print(f"  Package: {name} ({version})")
        print(f"{'='*70}")
        print(f"  {'CVE ID':<20} {'SEV':<10} {'Fix':<12} {'Src':<5}  Description")
        print(f"  {'-'*20} {'-'*10} {'-'*12} {'-'*5}  {'-'*40}")
        for cve in shown:
            desc = str(cve.get('description', ''))[:60]
            print(f"  {cve.get('cve_id',''):<20} {cve.get('severity',''):<10} {cve.get('fix_version',''):<12} {cve.get('source',''):<5}  {desc}")
        if truncated:
            print(f"  ... and {truncated} more CVE(s)")
        return

    c = pr.console()
    title = f"[bold white]{name}[/bold white] [dim]v{version}[/dim]"
    t = Table(title=title, show_header=True, header_style="bold cyan", border_style="dim blue", expand=True, box=None)
    t.add_column("CVE ID", style="bold yellow", width=16)
    t.add_column("Severity", width=12, justify="center")
    t.add_column("Description", ratio=1)
    t.add_column("Fix", style="bold green", width=12)

    for cve in shown:
        sev = str(cve.get("severity", "UNKNOWN")).upper()
        colors = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow", "LOW": "green"}
        s_c = colors.get(sev, "white")
        sev_style = f"[bold {s_c}]{sev}[/bold {s_c}]"

        desc = str(cve.get("description", ""))
        if len(desc) > 120:
            desc = desc[:117] + "..."

        t.add_row(
            str(cve.get("cve_id", "N/A")),
            sev_style,
            desc,
            str(cve.get("fix_version", "N/A"))
        )

    c.print(t)
    if truncated:
        c.print(f"  [dim]… and {truncated} more CVE(s) (use --limit to increase)[/dim]\n")
    else:
        c.print("")


def print_summary(pr: Printer, results: list[tuple[dict, list[dict]]], duration: float):
    total = len(results)
    vuln_pkgs = [(p, c) for p, c in results if c]
    clean = total - len(vuln_pkgs)
    sev_counts: dict[str, int] = {k: 0 for k in SEVERITY_WEIGHTS}
    for _, cves in vuln_pkgs:
        for cve in cves:
            s = cve.get("severity", "UNKNOWN")
            if s in sev_counts:
                sev_counts[s] += 1
    raw_score = sum(sev_counts.get(s, 0) * w for s, w in SEVERITY_WEIGHTS.items())
    risk_score = min(100, raw_score)

    if pr.no_color or not RICH_AVAILABLE:
        print("\n" + "="*60)
        print("  SCAN SUMMARY")
        print("="*60)
        print(f"  Packages scanned : {total}")
        print(f"  Vulnerable       : {len(vuln_pkgs)}")
        print(f"  Clean            : {clean}")
        print(f"  CRITICAL CVEs    : {sev_counts.get('CRITICAL',0)}")
        print(f"  HIGH CVEs        : {sev_counts.get('HIGH',0)}")
        print(f"  Risk Score       : {risk_score}/100")
        print(f"  Scan Duration    : {duration:.1f}s")
        print("="*60)
        return

    c = pr.console()
    risk_label, risk_color = "LOW RISK", "green"
    if risk_score >= 70:   risk_label, risk_color = "CRITICAL RISK", "red"
    elif risk_score >= 40: risk_label, risk_color = "HIGH RISK", "bright_red"
    elif risk_score >= 15: risk_label, risk_color = "MODERATE RISK", "yellow"

    c.print("\n")
    c.print(Columns([
        Panel(f"[bold cyan]{total}[/bold cyan]\n[dim]Total[/dim]",         border_style="dim cyan",  padding=(1, 2)),
        Panel(f"[bold red]{len(vuln_pkgs)}[/bold red]\n[dim]Vuln[/dim]",   border_style="red",       padding=(1, 2)),
        Panel(f"[bold {risk_color}]{risk_score}/100[/bold {risk_color}]\n[dim]Risk[/dim]", border_style=risk_color, padding=(1, 2)),
    ]))

    st = Table.grid(expand=False, padding=(0, 4))
    st.add_column(style="dim")
    st.add_column(style="bold white")
    st.add_row("CRITICAL:", str(sev_counts.get("CRITICAL", 0)))
    st.add_row("HIGH:",     str(sev_counts.get("HIGH",     0)))
    st.add_row("MEDIUM:",   str(sev_counts.get("MEDIUM",   0)))
    st.add_row("LOW:",      str(sev_counts.get("LOW",      0)))
    st.add_row("", "")
    st.add_row("Risk Level:", f"[bold {risk_color}]{risk_label}[/bold {risk_color}]")
    st.add_row("Duration:",   f"{duration:.1f}s")

    c.print(Panel(st, title="[bold white]Executive Summary[/bold white]", border_style="dim blue", expand=True))
    c.print("\n")