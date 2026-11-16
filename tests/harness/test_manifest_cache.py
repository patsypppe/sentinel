"""One tools/list per HTTP scan, shared by the rules that only read the manifest."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from typing import Any

import pytest

from server.common import parse, serve_background
from server.conformant import BEHAVIOUR
from server.conformant import dispatch as conformant_dispatch
from toolgauge.grade import run_scan
from toolgauge.probe.client import ManifestCache, Probe
from toolgauge.probe.transport import RawResponse

pytestmark = pytest.mark.unit

#: Rules whose only use of tools/list is to read the tools it carries.
MANIFEST_READERS = {
    "MCP/2026-07-28/MUST/tools-are-named",
    "MCP/2026-07-28/MUST/tools-declare-input-schema",
    "MCP/2026-07-28/MUST/tools-declare-valid-input-schema",
    "MCP/2026-07-28/SHOULD/tool-names-unique-within-server",
    "MCP/2026-07-28/SHOULD/tool-names-well-formed",
    "TOOLGAUGE/STYLE/tools-have-descriptions",
    "TOOLGAUGE/SECURITY/tool-description-injection",
}

DETERMINISM = "MCP/2026-07-28/SHOULD/tools-list-is-deterministic"


@pytest.fixture
def counted_endpoint() -> Iterator[tuple[Counter[str], str]]:
    methods: Counter[str] = Counter()

    def dispatch(handler: Any, body: bytes) -> tuple[int, dict[str, Any] | None]:
        payload = parse(body) or {}
        method = payload.get("method")
        if isinstance(method, str):
            methods[method] += 1
        return conformant_dispatch(handler, body)

    from tests.harness.conftest import _wait, free_port

    port = free_port()
    httpd, _ = serve_background(dispatch, port, banner="manifest cache", **BEHAVIOUR)
    endpoint = f"http://127.0.0.1:{port}/mcp"
    _wait(endpoint)
    methods.clear()
    yield methods, endpoint
    httpd.shutdown()
    httpd.server_close()


def test_rules_that_read_the_manifest_share_one_request(
    counted_endpoint: tuple[Counter[str], str],
) -> None:
    methods, endpoint = counted_endpoint
    report = run_scan(endpoint, only=MANIFEST_READERS)
    assert methods["tools/list"] == 1
    assert report.findings, "the rules ran and still produced findings"


def test_a_rule_that_tests_the_request_still_makes_every_call(
    counted_endpoint: tuple[Counter[str], str],
) -> None:
    methods, endpoint = counted_endpoint
    run_scan(endpoint, only={DETERMINISM})
    # The rule deliberately asks twenty times and the report's manifest hash
    # asks once more; a cache shared with the manifest readers must not turn
    # any of those into one.
    assert methods["tools/list"] == 21


def test_the_cache_holds_one_usable_reply_and_retries_an_unusable_one() -> None:
    cache = ManifestCache()
    calls: list[int] = []
    ok = RawResponse(200, {}, b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}', 0.0)

    def fetch() -> RawResponse:
        calls.append(1)
        return ok

    assert cache.get(legacy=False, fetch=fetch) is ok
    assert cache.get(legacy=False, fetch=fetch) is ok
    assert len(calls) == 1

    busy = RawResponse(503, {}, b"", 0.0)
    busy_calls: list[int] = []

    def busy_fetch() -> RawResponse:
        busy_calls.append(1)
        return busy

    assert cache.get(legacy=True, fetch=busy_fetch) is busy
    assert cache.get(legacy=True, fetch=busy_fetch) is busy
    assert len(busy_calls) == 2  # a refusal is not an answer to reuse
    assert cache.get(legacy=False, fetch=fetch) is ok
    assert len(calls) == 1


def test_a_probe_without_a_scan_cache_keeps_asking(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = Probe("http://127.0.0.1:9/mcp")
    calls: list[int] = []
    reply = RawResponse(200, {}, b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}', 0.0)

    def tools_list(**_: Any) -> RawResponse:
        calls.append(1)
        return reply

    monkeypatch.setattr(probe, "tools_list", tools_list)
    assert probe.manifest() is reply
    assert probe.manifest() is reply
    assert len(calls) == 2
    probe.close()
