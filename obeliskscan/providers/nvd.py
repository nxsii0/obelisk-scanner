from __future__ import annotations

import threading
from typing import Any

from obeliskscan.domain.severity import norm_severity
from obeliskscan.providers.http import HttpPolicy, get_json

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_cache_lock = threading.Lock()
_cache_by_keyword: dict[str, list[dict[str, Any]]] = {}
_cache_by_cve: dict[str, dict[str, Any] | None] = {}


def query_nvd(package: dict[str, Any], *, policy: HttpPolicy) -> list[dict[str, Any]]:
    name = package["name"]
    version = package.get("version", "") or ""
    keyword = f"{name} {version}".strip()
    key = keyword.lower()
    with _cache_lock:
        if key in _cache_by_keyword:
            return _cache_by_keyword[key]

    params = {"keywordSearch": keyword, "resultsPerPage": 20, "startIndex": 0}
    status, data = get_json(NVD_API, policy=policy, params=params, method="GET")
    if status == 0 or not isinstance(data, dict):
        res: list[dict[str, Any]] = []
        with _cache_lock:
            _cache_by_keyword[key] = res
        return res

    results: list[dict[str, Any]] = []
    for item in data.get("vulnerabilities", []) or []:
        cve_data = (item or {}).get("cve", {}) or {}
        cve_id = cve_data.get("id", "") or ""

        sev = "UNKNOWN"
        metrics = cve_data.get("metrics", {}) or {}
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for entry in metrics.get(metric_key, []) or []:
                base = ((entry or {}).get("cvssData", {}) or {}).get("baseSeverity", "")
                if base:
                    sev = norm_severity(base)
                    break
            if sev != "UNKNOWN":
                break

        desc = "N/A"
        for d in cve_data.get("descriptions", []) or []:
            if (d or {}).get("lang") == "en":
                desc = (d or {}).get("value", "N/A") or "N/A"
                break

        results.append(
            {
                "cve_id": cve_id,
                "osv_id": None,
                "severity": sev,
                "description": desc[:300],
                "fix_version": "N/A",
                "source": "NVD",
            }
        )

    with _cache_lock:
        _cache_by_keyword[key] = results
    return results


def query_nvd_by_cve_id(cve_id: str, *, policy: HttpPolicy) -> dict[str, Any] | None:
    cid = cve_id.upper()
    with _cache_lock:
        if cid in _cache_by_cve:
            return _cache_by_cve[cid]

    status, data = get_json(NVD_API, policy=policy, params={"cveId": cid}, method="GET")
    out = data if (status and isinstance(data, dict)) else None
    with _cache_lock:
        _cache_by_cve[cid] = out
    return out

