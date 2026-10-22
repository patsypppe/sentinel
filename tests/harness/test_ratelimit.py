"""The opt-in rate-limit rule: it may pass, it may stay silent, it may never fail."""

from __future__ import annotations

import itertools
from collections.abc import Iterator
from typing import Any

import pytest
from tests.harness.conftest import free_port

from sentinel.catalog.base import REGISTRY, Outcome
from sentinel.grade import run_scan
from sentinel.probe.client import Probe
from server import conformant
from server.common import error, parse, result, serve_background

pytestmark = pytest.mark.unit

RULE = next(r for r in REGISTRY.all() if r.slug == "tool-invocations-rate-limited")


@pytest.fixture
def limited_server() -> Iterator[tuple[dict[str, Any], str]]:
    """A server that throttles after `limit` calls, in the way its knobs say."""
    knobs: dict[str, Any] = {"limit": 5, "style": "http", "read_only": True}
    calls = itertools.count(1)

    def dispatch(handler: Any, body: bytes) -> tuple[int, dict[str, Any] | None]:
        payload = parse(body) or {}
        rid, method = payload.get("id"), payload.get("method")
        if method == "tools/list":
            tool = {"name": "t", "description": "d", "inputSchema": {"type": "object"}}
            if knobs["read_only"]:
                tool["annotations"] = {"readOnlyHint": True}  # type: ignore[assignment]
            return 200, result(rid, {"resultType": "complete", "tools": [tool]})
        if method == "tools/call":
            if next(calls) > knobs["limit"]:
                if knobs["style"] == "http":
                    return 429, error(rid, -32050, "slow down")
                return 200, error(rid, -32050, "Rate limit exceeded for this principal")
            return 200, result(rid, {"resultType": "complete", "content": []})
        return 404, error(rid, -32601, "no")

    port = free_port()
    httpd, _ = serve_background(dispatch, port, banner="ratelimit test")
    yield knobs, f"http://127.0.0.1:{port}/mcp"
    httpd.shutdown()
    httpd.server_close()


def verdict(endpoint: str, burst: int | None, *, safe: bool = False) -> tuple[Outcome, str]:
    context: dict[str, Any] = {} if burst is None else {"rate_limit_probe": burst}
    with Probe(endpoint, safe=safe, context=context) as probe:
        out = RULE.evaluate(probe)
    return out.outcome, out.detail


def test_it_does_nothing_unless_asked(limited_server: tuple[dict[str, Any], str]) -> None:
    knobs, endpoint = limited_server
    outcome, detail = verdict(endpoint, None)
    assert outcome is Outcome.INDETERMINATE and "--probe-rate-limit" in detail
    assert knobs["limit"] == 5  # and it did not touch the server


def test_a_throttled_burst_passes_whether_the_server_uses_429_or_a_message(
    limited_server: tuple[dict[str, Any], str],
) -> None:
    knobs, endpoint = limited_server
    outcome, detail = verdict(endpoint, 50)
    assert outcome is Outcome.PASS and "after 6 of a 50-call burst" in detail
    knobs["style"] = "message"
    outcome, _ = verdict(endpoint, 50)
    assert outcome is Outcome.PASS


def test_no_throttle_in_the_burst_is_silence_never_a_failure(
    limited_server: tuple[dict[str, Any], str],
) -> None:
    knobs, endpoint = limited_server
    knobs["limit"] = 10_000
    outcome, detail = verdict(endpoint, 20)
    assert outcome is Outcome.INDETERMINATE
    assert "not evidence the server has no limit" in detail


def test_safe_mode_will_not_flood_a_tool_that_is_not_read_only(
    limited_server: tuple[dict[str, Any], str],
) -> None:
    knobs, endpoint = limited_server
    knobs["read_only"] = False
    outcome, detail = verdict(endpoint, 50, safe=True)
    assert outcome is Outcome.INDETERMINATE and "safe mode" in detail


def test_the_burst_is_capped_whatever_is_asked(
    limited_server: tuple[dict[str, Any], str],
) -> None:
    from sentinel.catalog.must.ratelimit import MAX_BURST

    knobs, endpoint = limited_server
    knobs["limit"] = 10**9
    seen = {"n": 0}
    original = Probe.tools_call

    def counting(self: Probe, *a: Any, **k: Any) -> Any:
        seen["n"] += 1
        return original(self, *a, **k)

    Probe.tools_call = counting  # type: ignore[method-assign]
    try:
        verdict(endpoint, 10**9)
    finally:
        Probe.tools_call = original  # type: ignore[method-assign]
    assert seen["n"] == MAX_BURST


def test_a_plain_scan_never_floods_and_never_fails_the_rule(conformant_endpoint: str) -> None:
    report = run_scan(conformant_endpoint)
    finding = next(f for f in report.findings if f.rule.slug == "tool-invocations-rate-limited")
    assert finding.outcome is Outcome.INDETERMINATE
    assert conformant.TOOLS  # the conformant fixture has tools it could have been flooded through
