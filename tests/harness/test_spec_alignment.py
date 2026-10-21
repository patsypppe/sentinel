"""Rules corrected after running the official conformance suite's reference server.

Each test pins one correction from both sides: the behaviour the final
2026-07-28 text allows now passes (it failed in 0.3.0), and the behaviour the
rule exists to catch still fails.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar

import pytest
from conftest import _wait, free_port

from sentinel.catalog.base import REGISTRY, Outcome
from sentinel.probe.client import Probe
from server import conformant
from server.common import error, parse, result, serve_background

pytestmark = pytest.mark.unit


def _rule(rule_id: str) -> Any:
    return next(r for r in REGISTRY.all(include_deprecated=True) if r.id == rule_id)


def _evaluate(rule_id: str, endpoint: str, timeout: float = 5.0) -> Any:
    with Probe(endpoint, timeout=timeout) as probe:
        return _rule(rule_id).evaluate(probe)


def _serve(dispatch: Any, **behaviour: Any) -> Iterator[str]:
    port = free_port()
    httpd, _ = serve_background(dispatch, port, banner="alignment test", **behaviour)
    endpoint = f"http://127.0.0.1:{port}/mcp"
    _wait(endpoint)
    try:
        yield endpoint
    finally:
        httpd.shutdown()
        httpd.server_close()


# -- whitespace around header values ------------------------------------------

WHITESPACE = "MCP/2026-07-28/MUST/header-values-compared-without-surrounding-whitespace"


def _raw_comparing_dispatch(handler: Any, body: bytes) -> tuple[int, dict[str, Any] | None]:
    payload = parse(body) or {}
    raw = handler.headers.get("Mcp-Method")
    if raw is not None and raw != payload.get("method"):
        return 400, error(payload.get("id"), -32020, f"Mcp-Method is {raw!r}")
    return conformant.dispatch(handler, body)


@pytest.fixture
def raw_comparing() -> Iterator[str]:
    yield from _serve(_raw_comparing_dispatch)


def test_whitespace_rule_passes_a_server_that_trims(conformant_endpoint: str) -> None:
    assert _evaluate(WHITESPACE, conformant_endpoint).outcome is Outcome.PASS


def test_whitespace_rule_fails_a_server_that_compares_raw_bytes(raw_comparing: str) -> None:
    res = _evaluate(WHITESPACE, raw_comparing)
    assert res.outcome is Outcome.FAIL, res.detail


# -- unsupported-version error shape ------------------------------------------

SHAPE = "MCP/2026-07-28/MUST/unsupported-version-error-shape"


def _old_shape_dispatch(handler: Any, body: bytes) -> tuple[int, dict[str, Any] | None]:
    status, payload = conformant.dispatch(handler, body)
    err = (payload or {}).get("error") or {}
    if err.get("code") == -32022:
        err["data"] = {"supportedVersions": err["data"]["supported"]}
        return 200, payload
    return status, payload


@pytest.fixture
def old_shape() -> Iterator[str]:
    yield from _serve(_old_shape_dispatch)


def test_shape_passes_the_corrected_fixture(conformant_endpoint: str) -> None:
    assert _evaluate(SHAPE, conformant_endpoint).outcome is Outcome.PASS


def test_shape_fails_the_0_3_0_fixture_shape_and_names_the_field(old_shape: str) -> None:
    res = _evaluate(SHAPE, old_shape)
    assert res.outcome is Outcome.FAIL
    assert "not 400" in res.detail
    assert "supportedVersions" in res.detail


def test_the_retired_discover_rule_is_deprecated_and_superseded() -> None:
    old = _rule("MCP/2026-07-28/MUST/discover-without-negotiated-version")
    assert old.deprecated_in == "0.4.0"
    assert old.superseded_by == SHAPE
    assert old.id not in {r.id for r in REGISTRY.all()}


# -- subscriptions/listen with a real filter, read one message at a time ------

LIST_CHANGED = "MCP/2026-07-28/MUST/list-changed-advertised-truthfully"


class _StreamingHandler(BaseHTTPRequestHandler):
    """Advertises listChanged and answers subscriptions/listen with an SSE
    acknowledgement on a stream it then keeps open, as a real server does."""

    filters_seen: ClassVar[list[Any]] = []

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        payload = json.loads(body)
        method = payload.get("method")
        params = payload.get("params") or {}
        if method == "server/discover":
            self._json(result(payload["id"], {
                "resultType": "complete",
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {"listChanged": True}},
            }))
        elif method == "subscriptions/listen":
            type(self).filters_seen.append(params.get("notifications"))
            if not isinstance(params.get("notifications"), dict):
                self._json(error(payload["id"], -32602, "notifications is required"))
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            ack = {
                "jsonrpc": "2.0",
                "method": "notifications/subscriptions/acknowledged",
                "params": {"_meta": {"io.modelcontextprotocol/subscriptionId": "1"}},
            }
            self.wfile.write(b"event: message\ndata: " + json.dumps(ack).encode() + b"\n\n")
            self.wfile.flush()
            time.sleep(30)  # the stream stays open, as subscriptions do
        else:
            self._json(error(payload.get("id"), -32601, "unknown method"))

    def _json(self, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@pytest.fixture
def streaming() -> Iterator[str]:
    port = free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _StreamingHandler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    with socket.create_connection(("127.0.0.1", port), timeout=5):
        pass
    yield f"http://127.0.0.1:{port}/mcp"
    httpd.shutdown()
    httpd.server_close()


def test_list_changed_reads_the_acknowledgement_without_waiting_for_the_stream(
    streaming: str,
) -> None:
    started = time.perf_counter()
    res = _evaluate(LIST_CHANGED, streaming, timeout=10.0)
    elapsed = time.perf_counter() - started

    assert res.outcome is Outcome.PASS, res.detail
    assert "acknowledged" in res.detail
    assert elapsed < 5, f"waited {elapsed:.1f}s on a stream that never ends"
    assert _StreamingHandler.filters_seen[-1] == {"toolsListChanged": True}


def test_list_changed_still_fails_when_listen_is_missing(nonconformant_endpoint: str) -> None:
    assert _evaluate(LIST_CHANGED, nonconformant_endpoint).outcome is Outcome.FAIL


# -- 405 is asked of modern-only servers --------------------------------------

GET_DELETE = "MCP/2026-07-28/SHOULD/get-delete-405"


def _dual_era_dispatch(handler: Any, body: bytes) -> tuple[int, dict[str, Any] | None]:
    payload = parse(body) or {}
    if payload.get("method") == "initialize" and "_meta" not in (payload.get("params") or {}):
        return 200, result(payload.get("id"), {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "serverInfo": {"name": "dual", "version": "1"},
        })
    return conformant.dispatch(handler, body)


@pytest.fixture
def dual_era() -> Iterator[str]:
    yield from _serve(_dual_era_dispatch, bare_method_status=400)


def test_405_does_not_apply_to_a_dual_era_server(dual_era: str) -> None:
    res = _evaluate(GET_DELETE, dual_era)
    assert res.outcome is Outcome.NOT_APPLICABLE, res.detail


def test_405_still_fails_a_modern_only_server_that_keeps_get(nonconformant_endpoint: str) -> None:
    assert _evaluate(GET_DELETE, nonconformant_endpoint).outcome is Outcome.FAIL
