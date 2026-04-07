from __future__ import annotations

from typing import Any

from obeliskscan.providers.http import HttpPolicy, get_json


def query_internetdb(ip: str, *, policy: HttpPolicy) -> dict[str, Any] | None:
    status, data = get_json(f"https://internetdb.shodan.io/{ip}", policy=policy, method="GET")
    if status != 200 or not isinstance(data, dict):
        return None
    return data

