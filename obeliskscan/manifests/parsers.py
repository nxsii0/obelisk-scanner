from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

try:
    import toml  # type: ignore

    TOML_AVAILABLE = True
except ImportError:
    TOML_AVAILABLE = False


_REQ_BRACKETS_RE = re.compile(r"\[.*?\]")
_REQ_SPEC_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(?:==|===|>=|<=|~=|!=|>|<)\s*([\w.\-\+]+)")
_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9_.\-]+)")

_NPM_VER_RE = re.compile(r"^[\^~>=<]+([\d])")

_PIPFILE_SECTION_RE = re.compile(r"^\[(packages|dev-packages)\]$", re.I)
_PIPFILE_KV_RE = re.compile(r'^([A-Za-z0-9_.\-]+)\s*=\s*["\']?([^"\']*)["\']?')
_PIPFILE_VER_RE = re.compile(r"[\d][\d.\-\w]*")

_PYPROJECT_DEP_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(?:[><=!~]+)\s*([\w.\-]+)?")
_PYPROJECT_NAME_RE = re.compile(r"^([A-Za-z0-9_.\-]+)")
_PYPROJECT_VER_RE = re.compile(r"[\d][\d.\-\w]*")


def parse_requirements_txt(path: Path) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split("#")[0].strip()
        line = _REQ_BRACKETS_RE.sub("", line)
        m = _REQ_SPEC_RE.match(line)
        if m:
            packages.append({"name": m.group(1), "version": m.group(2), "ecosystem": "PyPI"})
            continue
        name = _REQ_NAME_RE.match(line)
        if name:
            packages.append({"name": name.group(1), "version": None, "ecosystem": "PyPI"})
    return packages


def parse_package_json(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    packages: list[dict[str, Any]] = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, ver_spec in (data.get(section, {}) or {}).items():
            ver = _NPM_VER_RE.sub(r"\1", str(ver_spec).strip())
            ver = ver.split(" ")[0].strip()
            packages.append({"name": name, "version": ver if re.search(r"\d", ver) else None, "ecosystem": "npm"})
    return packages


def parse_pipfile(path: Path) -> list[dict[str, Any]]:
    content = path.read_text(encoding="utf-8", errors="replace")
    packages: list[dict[str, Any]] = []
    in_section = False
    for line in content.splitlines():
        stripped = line.strip()
        if _PIPFILE_SECTION_RE.match(stripped):
            in_section = True
            continue
        if stripped.startswith("[") and in_section:
            in_section = False
            continue
        if not in_section or not stripped or stripped.startswith("#"):
            continue
        m = _PIPFILE_KV_RE.match(stripped)
        if m:
            name = m.group(1)
            ver_raw = m.group(2).strip()
            ver = _PIPFILE_VER_RE.search(ver_raw)
            packages.append({"name": name, "version": ver.group(0) if ver else None, "ecosystem": "PyPI"})
    return packages


def parse_pyproject_toml(path: Path) -> list[dict[str, Any]]:
    content = path.read_text(encoding="utf-8", errors="replace")
    packages: list[dict[str, Any]] = []
    if TOML_AVAILABLE:
        try:
            data = toml.loads(content)
        except Exception:
            return []
        for dep in (data.get("project", {}) or {}).get("dependencies", []) or []:
            m = _PYPROJECT_DEP_RE.match(dep)
            if m:
                packages.append({"name": m.group(1), "version": m.group(2), "ecosystem": "PyPI"})
            else:
                name = _PYPROJECT_NAME_RE.match(dep)
                if name:
                    packages.append({"name": name.group(1), "version": None, "ecosystem": "PyPI"})
        for name, spec in ((data.get("tool", {}) or {}).get("poetry", {}) or {}).get("dependencies", {}).items():
            if str(name).lower() == "python":
                continue
            if isinstance(spec, str):
                ver = _PYPROJECT_VER_RE.search(spec)
                packages.append({"name": name, "version": ver.group(0) if ver else None, "ecosystem": "PyPI"})
            elif isinstance(spec, dict):
                ver = _PYPROJECT_VER_RE.search(str(spec.get("version", "")))
                packages.append({"name": name, "version": ver.group(0) if ver else None, "ecosystem": "PyPI"})
    else:
        # Fallback: best-effort, line-based
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = re.match(r'^\s*"?([A-Za-z0-9_.\-]+)\s*(?:[><=!~^]+)\s*([\w.\-]+)?', line)
            if m:
                packages.append({"name": m.group(1), "version": m.group(2), "ecosystem": "PyPI"})
    return packages


MANIFEST_PARSERS_EXACT: dict[str, Callable[[Path], list[dict[str, Any]]]] = {
    "package.json": parse_package_json,
    "Pipfile": parse_pipfile,
    "pyproject.toml": parse_pyproject_toml,
}


def get_parser(path: Path) -> Callable[[Path], list[dict[str, Any]]] | None:
    name = path.name
    if name.endswith("requirements.txt") or name == "requirements.txt":
        return parse_requirements_txt
    return MANIFEST_PARSERS_EXACT.get(name)


def load_packages_from_file(path: Path) -> list[dict[str, Any]]:
    parser = get_parser(path)
    if not parser:
        return []
    try:
        pkgs = parser(path)
        for p in pkgs:
            p.setdefault("source_file", str(path))
        return pkgs
    except Exception:
        return []

