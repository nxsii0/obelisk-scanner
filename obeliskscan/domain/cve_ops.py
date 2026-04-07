from __future__ import annotations

from obeliskscan.domain.severity import SEVERITY_ORDER


def dedup_cves(cves: list[dict]) -> list[dict]:
    """Deduplicate by CVE ID, preferring higher severity and OSV on ties."""
    seen: dict[str, dict] = {}
    for cve in cves:
        cid = cve.get("cve_id", "")
        if not cid:
            continue
        if cid not in seen:
            seen[cid] = cve
            continue
        existing = seen[cid]
        if SEVERITY_ORDER.get(cve.get("severity", "UNKNOWN"), 0) > SEVERITY_ORDER.get(existing.get("severity", "UNKNOWN"), 0):
            seen[cid] = cve
        elif (
            cve.get("severity") == existing.get("severity")
            and cve.get("source") == "OSV"
            and existing.get("source") == "NVD"
        ):
            seen[cid] = cve
    return list(seen.values())


def filter_by_severity(cves: list[dict], min_sev: str) -> list[dict]:
    threshold = SEVERITY_ORDER.get(min_sev.upper(), 0)
    return [c for c in cves if SEVERITY_ORDER.get(c.get("severity", "UNKNOWN"), 0) >= threshold]

