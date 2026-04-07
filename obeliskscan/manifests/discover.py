from __future__ import annotations

import fnmatch
import os
from pathlib import Path


DEFAULT_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
}


DISCOVER_PATTERNS = ["*requirements*.txt", "package.json", "Pipfile", "pyproject.toml"]


def discover_manifests(directory: Path, *, patterns: list[str] | None = None, skip_dirs: set[str] | None = None) -> list[Path]:
    pats = patterns or DISCOVER_PATTERNS
    skips = skip_dirs or DEFAULT_SKIP_DIRS

    found: list[Path] = []
    # Single filesystem walk: much faster than N x rglob on large trees.
    for root, dirnames, filenames in os.walk(directory):
        dirnames[:] = [d for d in dirnames if d not in skips]
        for fn in filenames:
            for pat in pats:
                if fnmatch.fnmatch(fn, pat):
                    found.append(Path(root) / fn)
                    break
    # Dedup + stable order.
    return sorted(set(found))

