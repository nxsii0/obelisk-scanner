from __future__ import annotations

import html
import re
from pathlib import Path


def sanitize_target_name(name: str) -> str:
    # Handle URLs
    clean = name.split("://")[-1]
    clean = clean.split("/")[0] # Get only the domain/IP part for the folder name
    
    # Replace unsafe characters
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", clean).strip("._-")
    return safe or "target"


def html_escape(value: str) -> str:
    return html.escape(value)


def csv_safe(value: str) -> str:
    stripped = value.lstrip()
    if stripped.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value

