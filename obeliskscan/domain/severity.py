from __future__ import annotations

SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
SEVERITY_WEIGHTS: dict[str, int] = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}


def norm_severity(s: str | None) -> str:
    if not s:
        return "UNKNOWN"
    su = s.upper()
    return su if su in SEVERITY_ORDER else "UNKNOWN"


def severity_key(sev: str) -> int:
    return SEVERITY_ORDER.get(sev, 0)

