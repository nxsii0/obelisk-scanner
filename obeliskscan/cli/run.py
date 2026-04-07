from __future__ import annotations

import re
import sys
import time
from pathlib import Path

from obeliskscan.cli.args import build_parser
from obeliskscan.domain.cve_ops import dedup_cves, filter_by_severity
from obeliskscan.domain.severity import SEVERITY_ORDER
from obeliskscan.manifests.discover import discover_manifests
from obeliskscan.manifests.parsers import load_packages_from_file
from obeliskscan.providers.http import HttpPolicy
from obeliskscan.providers.nvd import query_nvd, query_nvd_by_cve_id
from obeliskscan.providers.osv import query_osv, query_osv_by_cve_id
from obeliskscan.reporting.export import export_csv, export_html, export_json, export_pdf
from obeliskscan.reporting.render import Printer, print_banner, print_clean_package, print_findings_table, print_summary
from obeliskscan.reporting.sanitize import sanitize_target_name
from obeliskscan.targets.fingerprint import scan_live_target

try:
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from concurrent.futures import ThreadPoolExecutor, as_completed


def _query_package(pkg: dict, *, policy: HttpPolicy) -> tuple[dict, list[dict]]:
    if "shodan_cves" in pkg:
        shodan_cves = pkg.get("shodan_cves") or []
        all_cves: list[dict] = []

        def _get_cve_info(cid: str) -> dict | None:
            cid = str(cid)
            osv_data = query_osv_by_cve_id(cid, policy=policy)
            if osv_data and "vulns" in osv_data and osv_data["vulns"]:
                v = osv_data["vulns"][0]
                sev = "UNKNOWN"
                for sv in v.get("severity", []) or []:
                    s = (sv or {}).get("score", "") or ""
                    if "CRITICAL" in s.upper(): sev = "CRITICAL"; break
                    elif "HIGH" in s.upper(): sev = "HIGH"
                    elif "MEDIUM" in s.upper() and sev not in ("HIGH", "CRITICAL"): sev = "MEDIUM"
                    elif "LOW" in s.upper() and sev == "UNKNOWN": sev = "LOW"
                db = v.get("database_specific", {}) or {}
                db_sev = (db.get("severity", "") or "").upper()
                if SEVERITY_ORDER.get(db_sev, 0) > SEVERITY_ORDER.get(sev, 0):
                    sev = db_sev
                summary = v.get("summary", "N/A")
                return {
                    "cve_id": cid,
                    "osv_id": v.get("id", ""),
                    "severity": sev,
                    "description": (summary[:300] if summary else "N/A"),
                    "fix_version": "N/A",
                    "source": "Shodan",
                }
            
            nvd_data = query_nvd_by_cve_id(cid, policy=policy)
            if nvd_data and nvd_data.get("vulnerabilities"):
                item = nvd_data["vulnerabilities"][0]
                cve_data = item.get("cve", {}) or {}
                sev = "UNKNOWN"
                metrics = cve_data.get("metrics", {}) or {}
                for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    for entry in metrics.get(mk, []) or []:
                        base = ((entry or {}).get("cvssData", {}) or {}).get("baseSeverity", "")
                        if base:
                            s = base.upper()
                            if s in SEVERITY_ORDER: sev = s; break
                    if sev != "UNKNOWN": break
                desc = "N/A"
                for d in cve_data.get("descriptions", []) or []:
                    if (d or {}).get("lang") == "en":
                        desc = (d or {}).get("value", "N/A") or "N/A"
                        break
                return {
                    "cve_id": cid,
                    "osv_id": None,
                    "severity": sev,
                    "description": desc[:300],
                    "fix_version": "N/A",
                    "source": "Shodan",
                }
            return {"cve_id": cid, "osv_id": None, "severity": "UNKNOWN", "description": "N/A", "fix_version": "N/A", "source": "Shodan"}

        with ThreadPoolExecutor(max_workers=min(10, len(shodan_cves))) as ex:
            futs = [ex.submit(_get_cve_info, cid) for cid in shodan_cves]
            for f in as_completed(futs):
                res = f.result()
                if res:
                    all_cves.append(res)
        return pkg, all_cves

    osv_results = query_osv(pkg, policy=policy)
    nvd_results = query_nvd(pkg, policy=policy)
    return pkg, dedup_cves(osv_results + nvd_results)


def _export_reports(results: list[tuple[dict, list[dict]]], packages: list[dict], duration: float, output_dir: Path, target_name: str, formats: str = "all"):
    output_dir = Path(output_dir)
    ts = time.strftime("%Y%m%d_%H%M%S")
    
    requested = {f.strip().lower() for f in formats.split(",")}
    all_formats = [("json", export_json), ("csv", export_csv), ("html", export_html), ("pdf", export_pdf)]
    
    for ext, fn in all_formats:
        if "all" not in requested and ext not in requested:
            continue
            
        target_dir = output_dir / target_name / ext
        target_dir.mkdir(parents=True, exist_ok=True)
        out_path = target_dir / f"obeliskscan_report_{ts}.{ext}"
        
        if ext == "json":
            fn(out_path, packages, results, duration)
        elif ext == "csv":
            fn(out_path, results)
        else:
            fn(out_path, packages, results, duration)


def run_scan(args) -> int:
    if not args.no_color:
        print_banner(no_color=args.no_color)
    pr = Printer(no_color=args.no_color)
    policy = HttpPolicy(timeout_sec=args.timeout, verify_tls=(not args.insecure))

    packages: list[dict] = []
    if args.target:
        ports: list[int] = []
        for p in args.target_ports.split(","):
            p = p.strip()
            if "-" in p:
                try:
                    start, end = map(int, p.split("-"))
                    ports.extend(range(start, end + 1))
                except ValueError:
                    pass
            elif p.isdigit():
                ports.append(int(p))
        packages = scan_live_target(args.target, ports, policy=policy, pr=pr)
    elif args.file:
        path = Path(args.file)
        if not path.exists():
            return 1
        packages = load_packages_from_file(path)
    elif args.dir:
        directory = Path(args.dir)
        if not directory.is_dir():
            return 1
        for m in discover_manifests(directory):
            packages.extend(load_packages_from_file(m))
    elif args.package:
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==)?\s*([\d][\d.\-\w]*)?", args.package)
        if not m:
            return 1
        name = m.group(1)
        ver = m.group(2) if m.lastindex and m.lastindex >= 2 else None
        packages = [{"name": name, "version": ver, "ecosystem": "PyPI"}]
    else:
        return 1

    if not packages:
        pr.print("\n[yellow]No packages or technologies detected. Exiting.[/yellow]")
        return 0

    ignored = {c.strip().upper() for c in args.ignore.split(",") if c.strip()}
    min_sev = "LOW" if args.severity == "ALL" else args.severity

    start = time.time()
    results: list[tuple[dict, list[dict]]] = []

    if RICH_AVAILABLE and not args.no_color:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=pr.console(),
            transient=True,
        ) as prog:
            task_id = prog.add_task("Querying APIs...", total=len(packages))
            with ThreadPoolExecutor(max_workers=min(8, len(packages))) as executor:
                futures = {executor.submit(_query_package, pkg, policy=policy): pkg for pkg in packages}
                for fut in as_completed(futures):
                    pkg_orig = futures[fut]
                    try:
                        pkg_r, cves = fut.result()
                    except Exception:
                        pkg_r, cves = pkg_orig, []
                    cves = filter_by_severity(cves, min_sev)
                    cves = [c for c in cves if c.get("cve_id") not in ignored]
                    cves.sort(key=lambda c: SEVERITY_ORDER.get(c.get("severity", "UNKNOWN"), 0), reverse=True)
                    results.append((pkg_r, cves))
                    prog.advance(task_id)
    else:
        with ThreadPoolExecutor(max_workers=min(8, len(packages))) as executor:
            futures = {executor.submit(_query_package, pkg, policy=policy): pkg for pkg in packages}
            for fut in as_completed(futures):
                pkg_orig = futures[fut]
                try:
                    pkg_r, cves = fut.result()
                except Exception:
                    pkg_r, cves = pkg_orig, []
                cves = filter_by_severity(cves, min_sev)
                cves = [c for c in cves if c.get("cve_id") not in ignored]
                cves.sort(key=lambda c: SEVERITY_ORDER.get(c.get("severity", "UNKNOWN"), 0), reverse=True)
                results.append((pkg_r, cves))

    duration = time.time() - start
    results.sort(key=lambda x: (0 if x[1] else 1, x[0]["name"].lower()))

    any_vulns = False
    for pkg, cves in results:
        if cves:
            any_vulns = True
            print_findings_table(pr, pkg, cves, limit=args.limit)
        elif args.verbose:
            print_clean_package(pr, pkg)
    print_summary(pr, results, duration)

    if not args.no_export:
        fmt = args.format
        if fmt is None:
            if sys.stdin.isatty() and not args.ci:
                from rich.prompt import Prompt
                pr.print("\n[bold cyan]Report Export[/bold cyan]")
                fmt = Prompt.ask(
                    "[white]Select formats[/white] [dim](comma-separated: html, pdf, json, csv, or 'all')[/dim]",
                    choices=["html", "pdf", "json", "csv", "all", "none"],
                    default="all",
                    console=pr.console()
                )
            else:
                fmt = "all"

        if fmt and fmt != "none":
            outdir = Path(args.output_dir)
            target_name = "local_scan"
            if args.target:
                target_name = sanitize_target_name(args.target)
            elif args.package:
                target_name = sanitize_target_name(args.package.split('=')[0].strip())
            elif packages and packages[0].get("source_file"):
                p = packages[0]["source_file"]
                if "live target" in p:
                    target_name = p.split(":")[-1].strip()
                else:
                    target_name = Path(p).stem
            _export_reports(results, packages, duration, outdir, target_name, formats=fmt)
        else:
            pr.print("\n[dim]Skipping export.[/dim]")

    if args.ci and any_vulns:
        return 1
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "scan":
        raise SystemExit(run_scan(args))
    parser.print_help()
    raise SystemExit(1)

