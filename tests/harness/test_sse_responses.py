"""A response carried as a text/event-stream event is still a response.

The transport lets a server answer a POST either as `application/json` or as an
SSE stream whose event carries the JSON-RPC message, and real servers do both.
A harness that only parsed bare JSON would grade every SSE-framed reply as "no
JSON-RPC response" -- a scanner bug that looks exactly like a server defect, and
against real servers the most common false failure there is.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from conftest import _wait, free_port

from sentinel.catalog.base import Outcome
from sentinel.grade import run_scan
from sentinel.probe.transport import RawResponse, sse_messages
from server.common import serve_background
from server.conformant import dispatch as conformant_dispatch

pytestmark = pytest.mark.unit


def _sse(body: bytes) -> RawResponse:
    return RawResponse(
        status=200,
        headers={"content-type": "text/event-stream; charset=utf-8"},
        body=body,
        elapsed_s=0.0,
    )


def test_one_event_is_parsed() -> None:
    resp = _sse(b'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n\n')
    assert resp.result() == {"ok": True}


def test_a_notification_before_the_response_is_skipped() -> None:
    resp = _sse(
        b'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n'
        b'data: {"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"no"}}\n\n'
    )
    assert resp.error_code() == -32601


def test_multi_line_data_is_joined_and_crlf_is_accepted() -> None:
    body = b'data: {"jsonrpc":"2.0",\r\ndata: "id":1,"result":{}}\r\n\r\n'
    assert sse_messages(body) == [{"jsonrpc": "2.0", "id": 1, "result": {}}]


def test_an_event_that_is_not_json_is_skipped_not_guessed() -> None:
    assert sse_messages(b"data: not json\n\n") == []
    assert _sse(b": keep-alive comment\n\n").envelope() is None


def test_a_bare_json_body_is_unaffected() -> None:
    resp = RawResponse(
        status=200,
        headers={"content-type": "application/json"},
        body=b'{"jsonrpc":"2.0","id":1,"result":{"a":1}}',
        elapsed_s=0.0,
    )
    assert resp.result() == {"a": 1}


@pytest.fixture
def sse_conformant() -> Iterator[str]:
    port = free_port()
    httpd, _ = serve_background(
        conformant_dispatch, port, banner="sse conformant", sse_framing=True
    )
    endpoint = f"http://127.0.0.1:{port}/mcp"
    _wait(endpoint)
    yield endpoint
    httpd.shutdown()
    httpd.server_close()


def test_the_conformant_fixture_framed_as_sse_grades_identically(
    conformant_endpoint: str, sse_conformant: str
) -> None:
    def verdicts(endpoint: str) -> dict[str, Outcome]:
        return {f.rule.id: f.outcome for f in run_scan(endpoint).findings}

    json_framed = verdicts(conformant_endpoint)
    sse_framed = verdicts(sse_conformant)
    differing = {
        rule: (json_framed[rule].value, sse_framed[rule].value)
        for rule in json_framed
        if json_framed[rule] is not sse_framed[rule]
    }
    assert not differing, f"rules that changed verdict only because of SSE framing: {differing}"
