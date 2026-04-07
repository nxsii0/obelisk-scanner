from __future__ import annotations

import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from obeliskscan.providers.http import HttpPolicy, get_session
from obeliskscan.providers.shodan import query_internetdb
from obeliskscan.reporting.render import Printer


def scan_live_target(target: str, ports: list[int], *, policy: HttpPolicy, pr: Printer | None = None) -> list[dict]:
    packages: list[dict] = []
    if not target.startswith(("http://", "https://")):
        url = f"http://{target}"
        host = target.split(":")[0]
    else:
        url = target
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname

    if pr:
        pr.print(f"[cyan]Scanning target host:[/cyan] {host}")

    try:
        ip = socket.gethostbyname(str(host))
        sdata = query_internetdb(ip, policy=policy)
        if sdata and sdata.get("vulns"):
            packages.append({"name": "network_host", "version": ip, "ecosystem": "Network", "shodan_cves": sdata["vulns"]})
    except Exception:
        pass

    try:
        sess = get_session(policy)
        r = sess.get(url, timeout=policy.timeout_sec, verify=policy.verify_tls, allow_redirects=True)
        for header, value in r.headers.items():
            h_low = header.lower()
            if h_low == "server":
                m = re.match(r"^([A-Za-z0-9\-]+)(?:/([\w.\-]+))?", value)
                if m:
                    packages.append({"name": m.group(1).lower(), "version": m.group(2), "ecosystem": "OS"})
            elif h_low == "x-powered-by":
                for part in value.split(","):
                    p = part.strip()
                    m = re.match(r"^([A-Za-z0-9\-]+)(?:/([\w.\-]+))?", p)
                    if m:
                        packages.append({"name": m.group(1).lower(), "version": m.group(2), "ecosystem": "Web"})
            elif h_low == "x-generator":
                m = re.match(r"^([A-Za-z0-9\-_\s]+)(?: ([\w.\-]+))?", value)
                if m:
                    n = m.group(1).strip().replace(" ", "_").lower()
                    packages.append({"name": n, "version": m.group(2), "ecosystem": "Web"})
    except Exception:
        pass

    open_ports: list[int] = []

    def check_port(p: int) -> int | None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((str(host), p)) == 0:
                s.close()
                return p
            s.close()
        except Exception:
            pass
        return None

    if ports:
        if pr:
            pr.print(f"[cyan]Scanning {len(ports)} target ports...[/cyan]")
        with ThreadPoolExecutor(max_workers=min(50, len(ports))) as ex:
            futures = [ex.submit(check_port, p) for p in ports]
            for fut in as_completed(futures):
                res = fut.result()
                if res is not None:
                    if pr:
                        pr.print(f"  [green]OPEN[/green]  Port {res}")
                    open_ports.append(res)

    for port in sorted(open_ports):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((str(host), port))
            s.settimeout(0.5)
            try:
                banner = s.recv(1024).decode("utf-8", "ignore")
            except socket.timeout:
                banner = ""
            if not banner:
                s.settimeout(2.0)
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                try:
                    banner = s.recv(1024).decode("utf-8", "ignore")
                except socket.timeout:
                    pass
            s.close()
            m = re.search(r"Server:\s*([A-Za-z0-9\-]+)(?:/([\w.\-]+))?", banner, re.I)
            if m:
                name = m.group(1).lower()
                ver = m.group(2)
                if not any(p["name"] == name for p in packages):
                    packages.append({"name": name, "version": ver, "ecosystem": "OS"})
            elif "SSH-" in banner:
                m = re.search(r"SSH-\d+\.\d+-([A-Za-z0-9_\-]+)_([\w.\-]+)", banner)
                if m:
                    packages.append({"name": m.group(1).lower(), "version": m.group(2), "ecosystem": "OS"})
            elif "220" in banner:
                m = re.search(r"220[ -]([A-Za-z0-9\-]+)(?:\s+v?([\w.\-]+))?", banner, re.I)
                if m:
                    packages.append({"name": m.group(1).lower(), "version": m.group(2), "ecosystem": "Server"})
        except Exception:
            pass

    unique: list[dict] = []
    seen: set[str] = set()
    for p in packages:
        k = f"{p['name']}:{p.get('version')}"
        if k not in seen:
            seen.add(k)
            p["source_file"] = f"live target: {host}"
            unique.append(p)
    return unique

