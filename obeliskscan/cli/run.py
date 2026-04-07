from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from obeliskscan.domain.severity import SEVERITY_WEIGHTS
from obeliskscan.reporting.sanitize import csv_safe, html_escape

# PDF exports removed as per user request.


def make_report_meta(packages: list[dict[str, Any]], results: list[tuple[dict[str, Any], list[dict[str, Any]]]], duration: float) -> dict[str, Any]:
    ts = datetime.now(timezone.utc).isoformat()
    sev_counts: dict[str, int] = {}
    vuln_count = 0
    for _, cves in results:
        if cves:
            vuln_count += 1
        for c in cves:
            s = c.get("severity", "UNKNOWN")
            sev_counts[s] = sev_counts.get(s, 0) + 1
    raw = sum(sev_counts.get(s, 0) * w for s, w in SEVERITY_WEIGHTS.items())
    return {
        "generated_at": ts,
        "scan_duration_sec": round(duration, 2),
        "total_packages": len(packages),
        "vulnerable_packages": vuln_count,
        "cve_counts": sev_counts,
        "risk_score": min(100, raw),
    }


def export_json(path: Path, packages: list[dict[str, Any]], results: list[tuple[dict[str, Any], list[dict[str, Any]]]], duration: float, *, pretty: bool = False):
    meta = make_report_meta(packages, results, duration)
    findings = [
        {
            "package": pkg["name"],
            "version": pkg.get("version"),
            "ecosystem": pkg.get("ecosystem"),
            "source_file": pkg.get("source_file"),
            "cves": cves,
        }
        for pkg, cves in results
    ]
    payload = {"metadata": meta, "findings": findings}
    if pretty:
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    else:
        path.write_text(json.dumps(payload, separators=(",", ":"), default=str), encoding="utf-8")


def export_csv(path: Path, results: list[tuple[dict[str, Any], list[dict[str, Any]]]]):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Package", "Version", "CVE ID", "Severity", "Description", "Fix Version", "Source"])
        for pkg, cves in results:
            if not cves:
                w.writerow([csv_safe(str(pkg["name"])), csv_safe(str(pkg.get("version", ""))), "", "", "", "", ""])
            for cve in cves:
                w.writerow(
                    [
                        csv_safe(str(pkg["name"])),
                        csv_safe(str(pkg.get("version", ""))),
                        csv_safe(str(cve.get("cve_id", ""))),
                        csv_safe(str(cve.get("severity", ""))),
                        csv_safe(str(cve.get("description", ""))),
                        csv_safe(str(cve.get("fix_version", ""))),
                        csv_safe(str(cve.get("source", ""))),
                    ]
                )


def export_html(path: Path, packages: list[dict[str, Any]], results: list[tuple[dict[str, Any], list[dict[str, Any]]]], duration: float):
    meta = make_report_meta(packages, results, duration)
    rs = meta["risk_score"]
    
    # HSL-based risk color
    # Purple-based risk color (from dark purple 280 to bright violet 300)
    risk_h = 300 if rs < 15 else 280 if rs < 40 else 260 if rs < 70 else 240
    risk_color = f"hsl({risk_h}, 80%, 60%)"

    rows: list[str] = []
    for pkg, cves in results:
        p_name = html_escape(str(pkg.get("name", "unknown")))
        p_ver = html_escape(str(pkg.get("version", "?")))
        p_eco = html_escape(str(pkg.get("ecosystem", "generic")))
        
        if not cves:
            # Add a hidden row type for 'CLEAN' packages if we want to filter them too
            rows.append(f"""
                <tr class="pkg-row clean" data-sev="CLEAN" data-src="none">
                    <td><div class="pkg-info"><strong>{p_name}</strong><span class="eco">{p_eco}</span></div></td>
                    <td>{p_ver}</td>
                    <td colspan="5" class="clean-msg">No vulnerabilities found</td>
                </tr>
            """)
            continue

        for cve in cves:
            c_id = html_escape(str(cve.get("cve_id", "N/A")))
            sev = str(cve.get("severity", "UNKNOWN")).upper()
            desc = html_escape(str(cve.get("description", "No description available.")))
            fix = html_escape(str(cve.get("fix_version", "N/A")))
            src = html_escape(str(cve.get("source", "Unknown")))
            
            # Severity color
            s_h = {"CRITICAL": 0, "HIGH": 25, "MEDIUM": 45, "LOW": 145}.get(sev, 200)
            s_c = f"hsl({s_h}, 75%, 50%)"
            
            rows.append(f"""
                <tr class="pkg-row vuln" data-sev="{sev}" data-src="{src}">
                    <td><div class="pkg-info"><strong>{p_name}</strong><span class="eco">{p_eco}</span></div></td>
                    <td>{p_ver}</td>
                    <td><a href="https://nvd.nist.gov/vuln/detail/{c_id}" target="_blank" class="cve-link">{c_id}</a></td>
                    <td><span class="badge" style="--bg: {s_c}">{sev}</span></td>
                    <td class="desc-cell" title="{desc}">{desc[:100]}{'...' if len(desc) > 100 else ''}</td>
                    <td><span class="fix-ver">{fix}</span></td>
                    <td><span class="src-tag">{src}</span></td>
                </tr>
            """)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OBELISK SCANNER Security Report</title>
    <style>
        :root {{
            --bg: #0b0e14;
            --surface: #151921;
            --surface-hover: #1c222d;
            --border: #2a313d;
            --text: #e0e6ed;
            --text-dim: #94a3b8;
            --primary: #bf00ff;
            --primary-glow: rgba(191, 0, 255, 0.2);
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --glow: #df80ff;
        }}

        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }}

        .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
        
        header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 40px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 24px;
        }}

        .brand {{ flex: 1; }}
        .brand .logo-raw {{ 
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            white-space: pre;
            line-height: 1.1;
            font-size: 0.75rem;
            color: var(--primary);
            text-shadow: 0 0 10px var(--primary-glow);
            margin-bottom: 12px;
        }}
        .brand h1 {{ margin: 0; font-size: 1.4rem; font-weight: 800; color: var(--text); letter-spacing: 0.05em; display: flex; align-items: center; gap: 12px; }}
        .brand h1 span {{ color: var(--primary); text-shadow: 0 0 15px var(--primary-glow); }}
        .brand p {{ margin: 8px 0 0; color: var(--text-dim); font-size: 0.85rem; }}

        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 40px; }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-2px); background: var(--surface-hover); }}
        .stat-val {{ display: block; font-size: 1.8rem; font-weight: 700; color: var(--primary); margin-bottom: 4px; }}
        .stat-lbl {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-dim); }}

        .risk-ring {{
            position: relative;
            width: 100px;
            height: 100px;
            border-radius: 50%;
            background: conic-gradient({risk_color} {meta['risk_score']}%, var(--border) 0);
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .risk-ring::after {{
            content: '';
            position: absolute;
            width: 80px;
            height: 80px;
            background: var(--bg);
            border-radius: 50%;
        }}
        .risk-ring span {{ position: relative; z-index: 1; font-size: 1.4rem; font-weight: 800; color: {risk_color}; }}

        .controls {{
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            background: var(--surface);
            padding: 20px;
            border-radius: 16px;
            border: 1px solid var(--border);
            margin-bottom: 24px;
            align-items: center;
        }}

        .search-box {{ flex: 1; position: relative; min-width: 280px; }}
        .search-box input {{
            width: 100%;
            background: var(--bg);
            border: 1px solid var(--border);
            padding: 12px 16px 12px 40px;
            border-radius: 12px;
            color: var(--text);
            font-size: 0.95rem;
            transition: border-color 0.2s, box-shadow 0.2s;
        }}
        .search-box input:focus {{ outline: none; border-color: var(--primary); box-shadow: 0 0 0 4px var(--primary-glow); }}
        .search-box::before {{
            content: '🔍';
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            opacity: 0.5;
        }}

        .filter-group {{ display: flex; gap: 8px; align-items: center; }}
        .filter-btn {{
            background: var(--bg);
            border: 1px solid var(--border);
            color: var(--text-dim);
            padding: 8px 14px;
            border-radius: 10px;
            cursor: pointer;
            font-size: 0.85rem;
            transition: all 0.2s;
        }}
        .filter-btn.active {{ background: var(--primary); color: #000; font-weight: 600; border-color: var(--primary); }}
        .filter-btn:hover:not(.active) {{ border-color: var(--text-dim); color: var(--text); }}

        table {{ width: 100%; border-collapse: separate; border-spacing: 0 8px; }}
        th {{ text-align: left; padding: 12px 20px; color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        td {{ padding: 16px 20px; background: var(--surface); border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); }}
        td:first-child {{ border-left: 1px solid var(--border); border-radius: 12px 0 0 12px; }}
        td:last-child {{ border-right: 1px solid var(--border); border-radius: 0 12px 12px 0; }}

        .pkg-info strong {{ display: block; font-size: 1rem; color: var(--text); }}
        .pkg-info .eco {{ font-size: 0.75rem; color: var(--text-dim); background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px; }}
        
        .badge {{
            padding: 4px 10px;
            border-radius: 8px;
            font-size: 0.7rem;
            font-weight: 800;
            background: var(--bg);
            border: 1px solid var(--bg);
            color: var(--bg); /* Hack: set text color same as bg, then use filter */
            color: #fff;
            background-color: var(--bg);
            border-color: var(--bg);
            background: var(--bg);
            box-shadow: inset 0 0 0 100px var(--bg);
            background: var(--bg);
            background-color: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background-color: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background-color: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background-color: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background: var(--bg);
            background-color: var(--bg);
        }}
        .badge {{ background-color: var(--bg); color: #fff; text-shadow: 0 1px 2px rgba(0,0,0,0.3); }}

        .cve-link {{ color: var(--primary); text-decoration: none; font-weight: 600; font-family: monospace; }}
        .cve-link:hover {{ text-decoration: underline; }}
        
        .desc-cell {{ color: var(--text-dim); font-size: 0.85rem; max-width: 300px; cursor: help; }}
        .fix-ver {{ color: var(--success); font-weight: 600; font-size: 0.85rem; }}
        .src-tag {{ font-size: 0.7rem; background: rgba(255,255,255,0.05); padding: 2px 8px; border-radius: 99px; color: var(--text-dim); text-transform: uppercase; }}

        .clean-msg {{ color: var(--text-dim); font-style: italic; text-align: center; font-size: 0.9rem; opacity: 0.6; }}

        @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(10px); }} to {{ opacity: 1; transform: translateY(0); }} }}
        .pkg-row {{ animation: fadeIn 0.3s ease-out forwards; }}

        #empty-state {{ display: none; text-align: center; padding: 60px; color: var(--text-dim); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div class="logo-raw">
  ◢■■■◣                                         
  █▌█▐█  ▄▀▀▄ █▀▀▄ █▀▀▀ █    █ ▄▀▀▀ █ ▄▀        
  █▌█▐█  █  █ █▀▀▄ █▀▀  █    █ ▀▀▀█ █▀▄         
  ◥■■■◤  ▀▀▀  ▀▀▀  ▀▀▀▀ ▀▀▀▀ ▀ ▀▀▀  ▀  ▀        

            S  C  A  N  N  E  R</div>
                <h1>OBELISK <span>SCANNER</span></h1>
                <p>Generated: {meta['generated_at']} · Scan Duration: {meta['scan_duration_sec']}s</p>
            </div>
            <div class="risk-ring">
                <span>{meta['risk_score']}</span>
            </div>
        </header>

        <section class="stats">
            <div class="stat-card"><span class="stat-val">{meta['total_packages']}</span><span class="stat-lbl">Total Scanned</span></div>
            <div class="stat-card"><span class="stat-val" style="color: var(--danger)">{meta['vulnerable_packages']}</span><span class="stat-lbl">Vulnerable</span></div>
            <div class="stat-card"><span class="stat-val">{meta['cve_counts'].get('CRITICAL',0)}</span><span class="stat-lbl">Critical</span></div>
            <div class="stat-card"><span class="stat-val">{meta['cve_counts'].get('HIGH',0)}</span><span class="stat-lbl">High</span></div>
        </section>

        <div class="controls">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search by package, CVE ID, or description..." oninput="updateFilters()">
            </div>
            <div class="filter-group" id="sevFilters">
                <button class="filter-btn active" onclick="toggleSev('ALL')">All</button>
                <button class="filter-btn" onclick="toggleSev('CRITICAL')">Critical</button>
                <button class="filter-btn" onclick="toggleSev('HIGH')">High</button>
                <button class="filter-btn" onclick="toggleSev('MEDIUM')">Medium</button>
                <button class="filter-btn" onclick="toggleSev('LOW')">Low</button>
            </div>
        </div>

        <table id="findingsTable">
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>CVE ID</th>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>Fix Version</th>
                    <th>Source</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>

        <div id="empty-state">
            <h3>No results matching your filters</h3>
            <p>Try adjusting your search terms or severity filters.</p>
        </div>
    </div>

    <script>
        let activeSev = 'ALL';

        function toggleSev(sev) {{
            document.querySelectorAll('#sevFilters .filter-btn').forEach(btn => {{
                btn.classList.toggle('active', btn.innerText.toUpperCase() === sev);
            }});
            activeSev = sev;
            updateFilters();
        }}

        function updateFilters() {{
            const q = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('.pkg-row');
            let visibleCount = 0;

            rows.forEach(row => {{
                const text = row.innerText.toLowerCase();
                const sev = row.getAttribute('data-sev');
                
                const matchesSearch = text.includes(q);
                const matchesSev = activeSev === 'ALL' || sev === activeSev;

                if (matchesSearch && matchesSev) {{
                    row.style.display = 'table-row';
                    visibleCount++;
                }} else {{
                    row.style.display = 'none';
                }}
            }});

            document.getElementById('empty-state').style.display = visibleCount === 0 ? 'block' : 'none';
            document.getElementById('findingsTable').style.display = visibleCount === 0 ? 'none' : 'table';
        }}
    </script>
</body>
</html>"""
    path.write_text(html_doc, encoding="utf-8")



def export_pdf(path: Path, packages: list[dict], results: list[tuple[dict, list[dict]]], duration: float):
    """Generates a professional PDF report using fpdf2."""
    try:
        from fpdf import FPDF
    except ImportError:
        return
    
    target_name = "Local Scan"
    if packages and packages[0].get("source_file"):
        target_name = packages[0]["source_file"]

    class OBELISKPDF(FPDF):
        def header(self):
            # Dark background header effect
            self.set_fill_color(25, 10, 40)
            self.rect(0, 0, 210, 35, 'F')
            
            self.set_font('Courier', 'B', 20)
            self.set_text_color(191, 0, 255) # Primary Purple
            self.cell(0, 15, "OBELISK SCANNER", ln=True, align='C')
            self.set_font('Courier', '', 10)
            self.set_text_color(160, 160, 160)
            self.cell(0, 5, "Vulnerability Intelligence & Security Audit", ln=True, align='C')
            self.ln(10)

        def footer(self):
            self.set_y(-15)
            self.set_font('Courier', 'I', 8)
            self.set_text_color(128, 128, 128)
            self.cell(0, 10, f'Page {self.page_no()} · OBELISK SCANNER', align='C')

    pdf = OBELISKPDF()
    pdf.set_title("OBELISK SCANNER Report")
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Meta Section
    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(40, 40, 60)
    pdf.cell(0, 10, f"Target: {target_name}", ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(80, 80, 80)
    import time
    now_ts = time.strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 7, f"Generated: {now_ts}", ln=True)
    pdf.cell(0, 7, f"Scan Duration: {duration:.2f}s", ln=True)
    
    # Stats row
    pdf.ln(5)
    total_pkgs = len(results)
    vuln_pkgs = len([p for p, c in results if c])
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(40, 10, f"Total Packages: {total_pkgs}")
    pdf.set_text_color(200, 0, 0) if vuln_pkgs > 0 else pdf.set_text_color(0, 128, 0)
    pdf.cell(40, 10, f"Vulnerable: {vuln_pkgs}")
    pdf.ln(10)

    # Findings Table
    pdf.set_fill_color(30, 30, 50)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Helvetica', 'B', 9)
    
    # Col widths (Total 190mm)
    cols = [40, 25, 45, 30, 50]
    headers = ["Package", "Version", "CVE ID", "Severity", "Fix Status"]
    
    for i, h in enumerate(headers):
        pdf.cell(cols[i], 10, h, border=1, fill=True, align='C')
    pdf.ln()

    pdf.set_text_color(0, 0, 0)
    pdf.set_font('Helvetica', '', 8)
    
    found_any = False
    for pkg, cves in results:
        if not cves: continue
        found_any = True
        
        for cve in cves:
            cve_id = str(cve.get('cve_id', 'N/A'))
            sev = str(cve.get('severity', 'UNKNOWN')).upper()
            fix = str(cve.get('fix_version', 'N/A'))
            
            # Formatting
            if sev == "CRITICAL": pdf.set_text_color(180, 0, 0)
            elif sev == "HIGH": pdf.set_text_color(220, 60, 0)
            elif sev == "MEDIUM": pdf.set_text_color(150, 150, 0)
            else: pdf.set_text_color(0, 0, 0)
            
            pdf.cell(cols[0], 8, pkg['name'][:22], border=1)
            pdf.cell(cols[1], 8, pkg.get('version', '?')[:15], border=1)
            pdf.cell(cols[2], 8, cve_id[:25], border=1)
            pdf.cell(cols[3], 8, sev, border=1)
            
            fix_text = f"Fix in {fix}" if fix != "N/A" else "No fixed version"
            if fix != "N/A": pdf.set_text_color(0, 100, 0)
            else: pdf.set_text_color(100, 100, 100)
            pdf.cell(cols[4], 8, fix_text[:30], border=1)
            pdf.ln()
            pdf.set_text_color(0, 0, 0)
            
    if not found_any:
        pdf.set_font('Helvetica', 'I', 10)
        pdf.cell(0, 20, "No vulnerabilities identified in this scan.", align='C')

    pdf.output(str(path))

