from __future__ import annotations

import threading
from typing import Any

from obeliskscan.domain.severity import SEVERITY_ORDER, norm_severity
from obeliskscan.providers.http import HttpPolicy, get_json

OSV_API = "https://api.osv.dev/v1/query"

_cache_lock = threading.Lock()
_cache_by_pkg: dict[tuple[str, str, str | None], list[dict[str, Any]]] = {}
_cache_by_cve: dict[str, dict[str, Any] | None] = {}


def query_osv(package: dict[str, Any], *, policy: HttpPolicy) -> list[dict[str, Any]]:
    name = package["name"]
    version = package.get("version")
    ecosystem = package.get("ecosystem", "PyPI")
    key = (ecosystem, name, version)
    with _cache_lock:
        if key in _cache_by_pkg:
            return _cache_by_pkg[key]

    payload: dict[str, Any] = {"package": {"name": name}}
    if ecosystem not in ("OS", "Web"):
        payload["package"]["ecosystem"] = ecosystem
    if version:
        payload["version"] = version

    status, data = get_json(OSV_API, policy=policy, json_body=payload, method="POST")
    if status == 0 or not isinstance(data, dict):
        res: list[dict[str, Any]] = []
        with _cache_lock:
            _cache_by_pkg[key] = res
        return res

    results: list[dict[str, Any]] = []
    for vuln in data.get("vulns", []) or []:
        vuln_id = vuln.get("id", "")
        aliases = vuln.get("aliases", []) or []
        cve_id = next((a for a in aliases if isinstance(a, str) and a.startswith("CVE-")), vuln_id)

        sev = "UNKNOWN"
        for sv in vuln.get("severity", []) or []:
            s = (sv or {}).get("score", "")
            su = str(s).upper()
            if "CRITICAL" in su:
                sev = "CRITICAL"
                break
            if "HIGH" in su:
                sev = "HIGH"
            elif "MEDIUM" in su and sev not in ("HIGH",):
                sev = "MEDIUM"
            elif "LOW" in su and sev == "UNKNOWN":
                sev = "LOW"

        db = vuln.get("database_specific", {}) or {}
        db_sev = norm_severity(db.get("severity", ""))
        if SEVERITY_ORDER.get(db_sev, 0) > SEVERITY_ORDER.get(sev, 0):
            sev = db_sev

        fix_version = None
        for affected in vuln.get("affected", []) or []:
            for rng in affected.get("ranges", []) or []:
                for ev in rng.get("events", []) or []:
                    if "fixed" in (ev or {}):
                        fix_version = ev["fixed"]
                        break
                if fix_version:
                    break
            if fix_version:
                break

        summary = vuln.get("summary", "N/A")
        results.append(
            {
                "cve_id": cve_id,
                "osv_id": vuln_id,
                "severity": sev,
                "description": (summary[:300] if summary else "N/A"),
                "fix_version": fix_version or "N/A",
                "source": "OSV",
            }
        )

    with _cache_lock:
        _cache_by_pkg[key] = results
    return results


def query_osv_by_cve_id(cve_id: str, *, policy: HttpPolicy) -> dict[str, Any] | None:
    cid = cve_id.upper()
    with _cache_lock:
        if cid in _cache_by_cve:
            return _cache_by_cve[cid]

    status, data = get_json(OSV_API, policy=policy, json_body={"id": cid}, method="POST")
    out = data if (status and isinstance(data, dict)) else None
    with _cache_lock:
        _cache_by_cve[cid] = out
    return out

