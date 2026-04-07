from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Ecosystem = Literal["PyPI", "npm", "OS", "Web", "Network", "Server"]


@dataclass(frozen=True, slots=True)
class Package:
    name: str
    version: str | None = None
    ecosystem: str = "PyPI"
    source_file: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
        }
        if self.source_file is not None:
            d["source_file"] = self.source_file
        d.update(self.extra)
        return d


@dataclass(frozen=True, slots=True)
class CVE:
    cve_id: str
    severity: str = "UNKNOWN"
    description: str = "N/A"
    fix_version: str = "N/A"
    source: str = "OSV"
    osv_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "osv_id": self.osv_id,
            "severity": self.severity,
            "description": self.description,
            "fix_version": self.fix_version,
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    package: Package
    cves: list[CVE]

