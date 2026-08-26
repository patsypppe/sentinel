"""The probe's own conformance.

A scanner that sends malformed requests grades every server as broken. The
spec's per-request `_meta` table marks protocolVersion and clientCapabilities
Required: Yes, and clientInfo Required: No.
"""

from __future__ import annotations

import json

import pytest

from sentinel.probe.client import (
    KEY_CLIENT_CAPABILITIES,
    KEY_CLIENT_INFO,
    KEY_PROTOCOL_VERSION,
    Probe,
)

pytestmark = pytest.mark.unit


def _meta_of(probe: Probe, **overrides: object) -> dict[str, object]:
    request = probe.build("tools/list", **overrides)  # type: ignore[arg-type]
    body = json.loads(request.body())
    return body["params"]["_meta"]


def test_every_request_carries_client_capabilities() -> None:
    with Probe("http://unused.invalid/mcp") as probe:
        meta = _meta_of(probe)
    assert KEY_CLIENT_CAPABILITIES in meta
    assert meta[KEY_CLIENT_CAPABILITIES] == {}


def test_every_request_carries_the_protocol_version() -> None:
    with Probe("http://unused.invalid/mcp") as probe:
        meta = _meta_of(probe)
    assert meta[KEY_PROTOCOL_VERSION] == "2026-07-28"


def test_client_info_is_still_sent() -> None:
    with Probe("http://unused.invalid/mcp") as probe:
        meta = _meta_of(probe)
    assert meta[KEY_CLIENT_INFO]["name"] == "sentinel-probe"


def test_client_capabilities_can_be_omitted_on_purpose() -> None:
    """A rule needs to send a deliberately malformed request to test the MUST."""
    with Probe("http://unused.invalid/mcp") as probe:
        meta = _meta_of(probe, omit_client_capabilities=True)
    assert KEY_CLIENT_CAPABILITIES not in meta


def test_client_capabilities_can_be_overridden() -> None:
    with Probe("http://unused.invalid/mcp") as probe:
        meta = _meta_of(probe, client_capabilities={"elicitation": {}})
    assert meta[KEY_CLIENT_CAPABILITIES] == {"elicitation": {}}


def test_every_request_carries_the_protocol_version_header() -> None:
    """"Every POST request to the MCP endpoint MUST include an
    MCP-Protocol-Version header." A server enforcing this rejects every
    request the harness sends today with 400 + HeaderMismatch."""
    with Probe("http://unused.invalid/mcp") as probe:
        request = probe.build("tools/list")
    assert request.headers["MCP-Protocol-Version"] == "2026-07-28"


def test_the_protocol_version_header_matches_the_body() -> None:
    """"The header value MUST match the io.modelcontextprotocol/protocolVersion
    field carried in the request body's _meta."
    """
    with Probe("http://unused.invalid/mcp") as probe:
        request = probe.build("tools/list")
    body = json.loads(request.body())
    assert request.headers["MCP-Protocol-Version"] == body["params"]["_meta"][KEY_PROTOCOL_VERSION]


def test_the_protocol_version_header_can_be_omitted_or_forced_apart() -> None:
    with Probe("http://unused.invalid/mcp") as probe:
        assert "MCP-Protocol-Version" not in probe.build(
            "tools/list", omit_protocol_version_header=True
        ).headers
        skewed = probe.build("tools/list", protocol_version_header="2025-11-25")
    assert skewed.headers["MCP-Protocol-Version"] == "2025-11-25"
    assert json.loads(skewed.body())["params"]["_meta"][KEY_PROTOCOL_VERSION] == "2026-07-28"


def test_the_accept_header_lists_both_content_types() -> None:
    """"The client MUST include an Accept header listing both application/json
    and text/event-stream as supported content types."
    """
    from sentinel.probe.transport import ACCEPT_VALUE

    assert "application/json" in ACCEPT_VALUE
    assert "text/event-stream" in ACCEPT_VALUE


def test_new_connection_is_a_separate_client_to_the_same_endpoint() -> None:
    """`tools-list-connection-independent` needs two genuinely separate clients."""
    with Probe("http://unused.invalid/mcp", bearer_token="t", timeout=3.0) as a:
        b = a.new_connection()
        try:
            assert b.endpoint == a.endpoint
            assert b is not a
            assert b._transport is not a._transport
            assert b._transport.bearer_token == "t"
            assert b._transport.timeout == 3.0
            assert b.protocol_version == a.protocol_version
        finally:
            b.close()


def test_a_notification_has_no_id() -> None:
    """A notification is a notification because it carries no id."""
    with Probe("http://unused.invalid/mcp") as probe:
        request = probe.build_notification("notifications/does-not-exist")
    body = json.loads(request.body())
    assert "id" not in body
    assert body["jsonrpc"] == "2.0"
    assert body["method"] == "notifications/does-not-exist"


def test_building_a_notification_leaves_the_request_alone() -> None:
    """`build` still produces a request with an id; only the copy loses it."""
    with Probe("http://unused.invalid/mcp") as probe:
        assert "id" in json.loads(probe.build("tools/list").body())


def test_transport_options_propagate_to_a_new_connection() -> None:
    """The second connection must differ in one respect: being a second one."""
    with Probe(
        "http://unused.invalid/mcp", verify=False, proxy="http://p:1", retries=5
    ) as a:
        b = a.new_connection()
        try:
            assert b._transport.verify is False
            assert b._transport.proxy == "http://p:1"
            assert b._transport.retries == 5
        finally:
            b.close()


def test_a_transport_error_is_retried_but_a_served_response_is_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retry transport failures only.

    Retrying a response the server actually sent would re-run side effects and
    corrupt every idempotency-sensitive rule in the catalog.
    """
    import httpx

    from sentinel.probe.transport import Request, Transport

    calls = {"n": 0}

    def flaky(*args: object, **kwargs: object) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ConnectError("boom")
        return httpx.Response(500, json={"jsonrpc": "2.0", "id": "1", "error": {"code": -1}})

    with Transport("http://unused.invalid/mcp", retries=2) as transport:
        monkeypatch.setattr(transport._client, "post", flaky)
        response = transport.send(
            Request(method="tools/list", params=None, request_id="1", headers={})
        )

    assert calls["n"] == 3          # two retries, then success
    assert response.status == 500   # and the 500 is NOT retried
    assert response.reached_server


def test_retries_are_bounded_and_the_failure_is_reported() -> None:
    """When every attempt fails the transport error is surfaced, not raised."""
    from sentinel.probe.transport import Request, Transport

    with Transport("http://127.0.0.1:1/mcp", timeout=1.0, retries=1) as transport:
        response = transport.send(Request(method="tools/list", request_id="1"))

    assert not response.reached_server
    assert response.status == 0
    assert response.transport_error
