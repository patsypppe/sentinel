"""The header contract, both halves.

`docs/HANDOFF.md` §8.2 asks for a demonstration rather than an assertion: Envoy
routes and authorizes on `Mcp-Method` / `Mcp-Name` with no body parsing
anywhere, and the broker rejects a body that disagrees with those headers.

Routed by header, rejected by body check. That pair is the demonstration.
"""

from __future__ import annotations

import json
import pathlib
import time
from typing import Any

import httpx
import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
ENVOY_CONFIG = REPO_ROOT / "envoy" / "envoy.yaml"

TRUSTED = "http://localhost:10000/mcp"
UNTRUSTED = "http://localhost:10001/mcp"
BROKER = "http://localhost:8080/mcp"

ROUTER_FILTER = "envoy.filters.http.router"

#: Filters that can read or buffer a request body. The point of the header
#: contract is that a gateway needs none of them, so their presence would quietly
#: dissolve the property this file exists to prove.
BODY_READING_FILTERS = {
    "envoy.filters.http.lua",
    "envoy.filters.http.wasm",
    "envoy.filters.http.buffer",
    "envoy.filters.http.ext_proc",
    "envoy.filters.http.json_to_metadata",
    "envoy.filters.http.grpc_json_transcoder",
    "envoy.filters.http.grpc_web",
    "envoy.filters.http.compressor",
    "envoy.filters.http.decompressor",
}


def _envoy_http_filters() -> list[dict[str, Any]]:
    config = yaml.safe_load(ENVOY_CONFIG.read_text())
    filters: list[dict[str, Any]] = []
    for listener in config["static_resources"]["listeners"]:
        for chain in listener["filter_chains"]:
            for net_filter in chain["filters"]:
                hcm = net_filter.get("typed_config", {})
                filters.extend(hcm.get("http_filters", []))
    return filters


# --------------------------------------------------------------------------
# Static config checks. Marked `unit` deliberately: §10 (WP-2 pitfalls) says an
# Envoy config error denies valid traffic silently, so this belongs in the fast
# job that runs on every commit, not only in the docker-backed one.
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_envoy_parses() -> None:
    config = yaml.safe_load(ENVOY_CONFIG.read_text())
    assert config["static_resources"]["listeners"], "envoy.yaml declares no listeners"


@pytest.mark.unit
def test_envoy_has_no_body_parsing_filter() -> None:
    """The whole architectural claim, asserted against the parsed filter chain.

    Grepping for the word "body" would pass for the wrong reason — the config
    contains `direct_response.body`, which is a *response* body. Parsing the
    file and looking at what is actually in `http_filters` is the check that
    means what it says.
    """
    names = [f["name"] for f in _envoy_http_filters()]

    assert names, "no http_filters found — the config shape changed and this test is now blind"

    offending = sorted(set(names) & BODY_READING_FILTERS)
    assert not offending, (
        f"Envoy is configured with body-reading filter(s) {offending}. "
        "The header contract exists so a gateway can route and authorize without "
        "parsing the JSON body; adding one of these dissolves that property."
    )
    assert set(names) == {ROUTER_FILTER}, (
        f"expected only {ROUTER_FILTER} in the filter chain, found {sorted(set(names))}. "
        "A new filter may be harmless, but it needs to be reviewed against §8.2 "
        "rather than added silently."
    )


@pytest.mark.unit
def test_ops_family_is_denied_by_header_match_alone() -> None:
    """The authorization rule must be expressible in headers, or it is not a
    demonstration of the header contract at all."""
    config = yaml.safe_load(ENVOY_CONFIG.read_text())

    deny_routes = [
        route
        for listener in config["static_resources"]["listeners"]
        for chain in listener["filter_chains"]
        for net_filter in chain["filters"]
        for vhost in net_filter["typed_config"]["route_config"]["virtual_hosts"]
        for route in vhost["routes"]
        if route.get("name") == "deny_ops_family"
    ]

    assert len(deny_routes) == 1, "expected exactly one deny_ops_family route"
    matchers = {h["name"] for h in deny_routes[0]["match"]["headers"]}
    assert matchers == {"Mcp-Method", "Mcp-Name"}, (
        f"the ops.* denial matches on {matchers}; it must decide from the two "
        "contract headers and nothing else"
    )
    assert deny_routes[0]["direct_response"]["status"] == 403


# --------------------------------------------------------------------------
# Live checks through the running gateway.
# --------------------------------------------------------------------------


def _wait_for(url: str, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    last: httpx.RequestError | None = None
    while time.time() < deadline:
        try:
            httpx.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "server/discover"},
                       headers={"Mcp-Method": "server/discover", "Mcp-Name": "server/discover"},
                       timeout=3.0)
            return
        except httpx.RequestError as exc:
            # Connection refused / DNS / timeout all mean the same thing here:
            # not up yet. A response of any status means it is.
            last = exc
            time.sleep(1.0)
    raise RuntimeError(f"{url} never became ready: {last}")


@pytest.fixture(scope="module")
def gateway() -> None:
    _wait_for(TRUSTED)


@pytest.mark.e2e
def test_trusted_listener_routes_on_the_method_header(gateway: None) -> None:
    resp = httpx.post(
        TRUSTED,
        content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover"}),
        headers={
            "Content-Type": "application/json",
            "Mcp-Method": "server/discover",
            "Mcp-Name": "server/discover",
        },
        timeout=10.0,
    )
    assert resp.status_code == 200
    assert resp.headers.get("X-Sentinel-Route") == "trusted-full"
    assert resp.json()["result"]["resultType"] == "complete"


@pytest.mark.e2e
def test_gateway_refuses_a_request_it_cannot_route(gateway: None) -> None:
    """No `Mcp-Method` means the gateway would have to read the body to route.
    It refuses instead, which is the behaviour the contract is for."""
    resp = httpx.post(
        TRUSTED,
        content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover"}),
        headers={"Content-Type": "application/json"},
        timeout=10.0,
    )
    assert resp.status_code == 400
    assert resp.headers.get("X-Sentinel-Route") == "reject-unroutable"


@pytest.mark.e2e
def test_untrusted_listener_denies_the_ops_family(gateway: None) -> None:
    """Authorized from two headers. The gateway never sees the arguments."""
    resp = httpx.post(
        UNTRUSTED,
        content=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "ops.deployment_apply", "arguments": {"plan": "hnd_x"}},
            }
        ),
        headers={
            "Content-Type": "application/json",
            "Mcp-Method": "tools/call",
            "Mcp-Name": "ops.deployment_apply",
        },
        timeout=10.0,
    )
    assert resp.status_code == 403
    assert resp.headers.get("X-Sentinel-Route") == "untrusted-deny-ops"


@pytest.mark.e2e
def test_untrusted_listener_allows_the_warehouse_family(gateway: None) -> None:
    resp = httpx.post(
        UNTRUSTED,
        content=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "warehouse.query", "arguments": {}},
            }
        ),
        headers={
            "Content-Type": "application/json",
            "Mcp-Method": "tools/call",
            "Mcp-Name": "warehouse.query",
        },
        timeout=10.0,
    )
    # The gateway allowed it through; the broker answers on its own terms
    # (tools/call has no registered handler until WP-3).
    assert resp.status_code == 200
    assert resp.headers.get("X-Sentinel-Route") == "untrusted-allow"


@pytest.mark.e2e
def test_routed_by_header_rejected_by_body_check(gateway: None) -> None:
    """The demonstration §8.2 asks for, in one request.

    The body calls `ops.deployment_apply`. The headers claim `warehouse.query`,
    so Envoy's `deny_ops_family` rule does not match and the request is routed
    through — the gateway did exactly what it promised, using only headers. The
    broker then compares the headers against the body and refuses with -32020.

    Neither half is sufficient alone. The gateway cannot see the body by design;
    the server can, and that is what makes the headers binding rather than
    advisory.
    """
    resp = httpx.post(
        UNTRUSTED,
        content=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "ops.deployment_apply", "arguments": {}},
            }
        ),
        headers={
            "Content-Type": "application/json",
            "Mcp-Method": "tools/call",
            "Mcp-Name": "warehouse.query",
        },
        timeout=10.0,
    )

    assert resp.headers.get("X-Sentinel-Route") == "untrusted-allow", (
        "Envoy should have routed this through: its policy matches on headers, "
        "and the headers say warehouse.query"
    )
    body = resp.json()
    assert body["error"]["code"] == -32020, (
        f"the broker must reject a body that disagrees with the headers, got {body}"
    )
    assert body["error"]["data"]["header"] == "Mcp-Name"
