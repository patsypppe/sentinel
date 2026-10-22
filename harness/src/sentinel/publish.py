"""Send a scan's report to a `sentinel-server`.

Additive and never fatal. The scan's verdict is the product: a service that is down,
slow or misconfigured must not turn a clean scan red, and must not turn a failing
one green. So a publish failure is a warning on stderr and nothing more, and the exit
code is decided before this is called.

The token comes from the environment (`SENTINEL_PUBLISH_TOKEN`), never from a flag,
so it does not end up in a shell history or a CI log line.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

import httpx

__all__ = ["PublishResult", "publish"]

PATH = "/api/v1/scans"


class PublishResult:
    __slots__ = ("detail", "ok")

    def __init__(self, ok: bool, detail: str) -> None:
        self.ok = ok
        self.detail = detail


def publish(
    base_url: str,
    report: Mapping[str, Any],
    *,
    token: str | None = None,
    timeout: float = 10.0,
    verify: bool | str = True,
    env: Mapping[str, str] | None = None,
) -> PublishResult:
    """POST the v2 JSON report. Returns the outcome; never raises."""
    environment = os.environ if env is None else env
    bearer = token or environment.get("SENTINEL_PUBLISH_TOKEN")
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    url = base_url.rstrip("/") + PATH
    try:
        response = httpx.post(
            url, content=json.dumps(report), headers=headers, timeout=timeout, verify=verify
        )
    except httpx.HTTPError as exc:
        return PublishResult(False, f"could not reach {url}: {exc}")
    if response.status_code >= 400:
        return PublishResult(False, f"{url} answered HTTP {response.status_code}")
    return PublishResult(True, f"published to {url}")
