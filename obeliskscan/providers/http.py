from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


DEFAULT_UA = "OBELISK SCANNER/1.0"


@dataclass(frozen=True, slots=True)
class HttpPolicy:
    timeout_sec: int = 10
    verify_tls: bool = True
    user_agent: str = DEFAULT_UA
    max_retries: int = 4
    backoff_factor: float = 0.6
    pool_connections: int = 20
    pool_maxsize: int = 50


_session_lock = threading.Lock()
_session: requests.Session | None = None


def get_session(policy: HttpPolicy) -> requests.Session:
    """Create (once) and return a configured requests.Session for pooling + retries."""
    global _session
    if _session is not None:
        return _session
    with _session_lock:
        if _session is not None:
            return _session
        s = requests.Session()
        s.headers.update({"User-Agent": policy.user_agent})

        retry = Retry(
            total=policy.max_retries,
            connect=policy.max_retries,
            read=policy.max_retries,
            status=policy.max_retries,
            backoff_factor=policy.backoff_factor,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST"),
            raise_on_status=False,
            respect_retry_after_header=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=policy.pool_connections,
            pool_maxsize=policy.pool_maxsize,
        )
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        _session = s
        return s


def get_json(
    url: str,
    *,
    policy: HttpPolicy,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    method: str = "GET",
) -> tuple[int, dict[str, Any] | None]:
    sess = get_session(policy)
    try:
        if method.upper() == "POST":
            resp = sess.post(url, params=params, json=json_body, timeout=policy.timeout_sec, verify=policy.verify_tls)
        else:
            resp = sess.get(url, params=params, timeout=policy.timeout_sec, verify=policy.verify_tls)
    except requests.RequestException:
        return 0, None

    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, None

