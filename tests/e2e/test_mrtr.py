"""Multi Round-Trip Requests, end to end over HTTP.

`docs/HANDOFF.md` §10 (WP-6) definition of done:

    ops.deployment_apply → input_required → approve → retry completes →
    replay the identical retry → identical response, ONE deployment.

The Go integration suite proves the engine. This proves the property survives
the whole stack — envelope, header contract, dispatch, scope check and tool —
which is a different claim and the one a client actually experiences.
"""

from __future__ import annotations

import functools
import json
import os
import pathlib
import shutil
import subprocess
import time
import uuid
from typing import Any

import httpx
import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

BROKER = "http://localhost:8080/mcp"
PROTOCOL = "2026-07-28"

OPERATOR = "00000000-0000-0000-0000-0000000000a2"
ANALYST = "00000000-0000-0000-0000-0000000000a1"

#: The audience this broker was issued for, and one it was not. Both tokens are
#: correctly signed by the same issuer; only the `aud` claim differs, which is
#: exactly the token an attacker who compromised the other service would hold.
THIS_SERVER = "https://broker.sentinel.local"
OTHER_SERVER = "https://billing.sentinel.local"

pytestmark = pytest.mark.e2e


@functools.cache
def mint(principal: str, scopes: str, audience: str = THIS_SERVER) -> str:
    """Mint a token with `broker mint-token`, reaching the same seed-derived key
    the running broker validates against."""
    env = {
        **os.environ,
        "BROKER_OAUTH_DEV_SEED": "a" * 64,
        "BROKER_OAUTH_ISSUER": "https://issuer.sentinel.local",
        "BROKER_OAUTH_AUDIENCE": THIS_SERVER,
    }
    go = shutil.which("/opt/homebrew/bin/go") or shutil.which("go") or "go"
    proc = subprocess.run(
        [go, "run", "./broker/cmd/broker", "mint-token",
         "--principal", principal, "--audience", audience, "--scopes", scopes],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, check=True,
    )
    return proc.stdout.strip()


def call(
    method: str,
    params: dict[str, Any] | None = None,
    *,
    principal: str = OPERATOR,
    scopes: str = "ops:plan ops:apply warehouse:read warehouse:describe",
    mcp_name: str | None = None,
    audience: str = THIS_SERVER,
) -> dict[str, Any]:
    """Send one JSON-RPC request.

    Every retry gets a NEW JSON-RPC id, deliberately: §8.5 requires correlation
    through the sealed requestState alone, so a server that correlated on the id
    would fail these tests rather than pass them by accident.
    """
    body = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": {**(params or {}), "_meta": {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL,
        }},
    }
    headers = {
        "Content-Type": "application/json",
        "Mcp-Method": method,
        "Authorization": "Bearer " + mint(principal, scopes, audience),
    }
    # Mcp-Name only where the header table defines it -- tools/call,
    # resources/read, prompts/get. server/discover has no params.name or
    # params.uri, so a header naming it would assert a body value that does not
    # exist, and the broker refuses one.
    name = mcp_name if mcp_name is not None else (params or {}).get("name")
    if name is not None:
        headers["Mcp-Name"] = name

    resp = httpx.post(
        BROKER,
        content=json.dumps(body),
        headers=headers,
        timeout=30.0,
    )
    resp.raise_for_status()
    return resp.json()


@pytest.fixture(scope="module", autouse=True)
def broker_ready() -> None:
    deadline = time.time() + 90
    last: Exception | None = None
    while time.time() < deadline:
        try:
            out = call("server/discover")
            if "result" in out:
                return
        except httpx.RequestError as exc:
            last = exc
        time.sleep(1.0)
    raise RuntimeError(f"broker never became ready: {last}")


def make_plan() -> str:
    out = call("tools/call", {
        "name": "ops.deployment_plan",
        "arguments": {"service": "checkout", "version": "1.4.2", "replicas": 3},
    })
    assert "error" not in out, out
    # structuredContent is raw JSON in the envelope, so it arrives already
    # parsed — it is not a JSON string that needs decoding again.
    return str(out["result"]["structuredContent"]["handle"])


def test_plan_changes_nothing_and_returns_a_handle() -> None:
    handle = make_plan()
    assert handle.startswith("hnd_"), handle


def test_irreversible_tool_returns_input_required() -> None:
    handle = make_plan()
    out = call("tools/call", {"name": "ops.deployment_apply", "arguments": {"plan": handle}})

    assert "error" not in out, out
    result = out["result"]
    assert result["resultType"] == "input_required", (
        f"an irreversible tool must ask before acting, got {result['resultType']}"
    )
    assert result["inputRequests"], "input_required must carry inputRequests"
    assert result["requestState"], "input_required must carry a requestState"
    assert result["inputRequests"][0]["destructive"] is True


def test_full_round_trip_deploys_exactly_once() -> None:
    """The WP-6 definition of done, in one test."""
    handle = make_plan()

    first = call("tools/call", {"name": "ops.deployment_apply", "arguments": {"plan": handle}})
    state = first["result"]["requestState"]

    retry_args = {
        "plan": handle,
        "requestState": state,
        "inputResponses": {"confirm": True},
    }

    completed = call("tools/call", {"name": "ops.deployment_apply", "arguments": retry_args})
    assert "error" not in completed, completed
    assert completed["result"]["resultType"] == "complete"
    body = completed["result"]["structuredContent"]
    assert body["deployed"] is True
    deployment_id = body["deploymentId"]

    # Replay the IDENTICAL retry five times. Each is a new JSON-RPC request with
    # a new id, exactly as a flaky client would send.
    for i in range(5):
        replayed = call("tools/call", {"name": "ops.deployment_apply", "arguments": retry_args})
        assert "error" not in replayed, replayed

        again = replayed["result"]["structuredContent"]
        assert again["deploymentId"] == deployment_id, (
            f"replay {i} produced a different deployment id — it deployed again"
        )
        original_content = completed["result"]["structuredContent"]
        assert replayed["result"]["structuredContent"] == original_content, (
            f"replay {i} differs from the original result"
        )
        assert "already completed" in replayed["result"]["content"][0]["text"], (
            "a replay must say so, or an operator reading the transcript cannot tell "
            "one deployment from two"
        )


def test_mutated_retry_is_rejected() -> None:
    approved = make_plan()
    other = make_plan()

    first = call("tools/call", {"name": "ops.deployment_apply", "arguments": {"plan": approved}})
    state = first["result"]["requestState"]

    out = call("tools/call", {"name": "ops.deployment_apply", "arguments": {
        "plan": other,
        "requestState": state,
        "inputResponses": {"confirm": True},
    }})
    assert "error" in out, "a retry naming a different plan must be refused"
    assert out["error"]["code"] == 1003, out["error"]


def test_tampered_request_state_is_rejected() -> None:
    handle = make_plan()
    first = call("tools/call", {"name": "ops.deployment_apply", "arguments": {"plan": handle}})
    state = first["result"]["requestState"]

    out = call("tools/call", {"name": "ops.deployment_apply", "arguments": {
        "plan": handle,
        "requestState": state[:-2] + ("AA" if not state.endswith("AA") else "BB"),
        "inputResponses": {"confirm": True},
    }})
    assert "error" in out, "a tampered requestState must be refused"
    assert out["error"]["code"] == 1004, out["error"]


def test_cross_principal_retry_is_rejected() -> None:
    """A leaked requestState does not let another principal complete the flow."""
    handle = make_plan()
    first = call("tools/call", {"name": "ops.deployment_apply", "arguments": {"plan": handle}})
    state = first["result"]["requestState"]

    out = call(
        "tools/call",
        {"name": "ops.deployment_apply", "arguments": {
            "plan": handle,
            "requestState": state,
            "inputResponses": {"confirm": True},
        }},
        principal=ANALYST,
        scopes="ops:plan ops:apply",  # scopes are not the control being tested
    )
    assert "error" in out, "another principal completed the flow"


def test_leaked_plan_handle_is_refused_for_another_principal() -> None:
    """Demo step 7: present a leaked handle as a different principal."""
    handle = make_plan()

    out = call(
        "tools/call",
        {"name": "ops.deployment_apply", "arguments": {"plan": handle}},
        principal=ANALYST,
        scopes="ops:plan ops:apply",
    )
    assert "error" in out, "a leaked handle resolved for a different principal"
    assert out["error"]["code"] == 1000, out["error"]
    # One message for every cause, so nothing distinguishes "not yours" from
    # "no such handle".
    for cause in ("does not exist", "not yours", "expired", "revoked"):
        assert cause in out["error"]["message"], out["error"]["message"]


def test_scope_denial_names_the_missing_scope() -> None:
    handle = make_plan()
    out = call(
        "tools/call",
        {"name": "ops.deployment_apply", "arguments": {"plan": handle}},
        scopes="warehouse:read",
    )
    assert "error" in out
    assert out["error"]["code"] == 1007, out["error"]
    assert out["error"]["data"]["requiredScope"] == "ops:apply"


def test_token_for_another_audience_is_rejected() -> None:
    """The specification's explicit MUST NOT, over the wire.

    The token is correctly signed by the same issuer and names a real principal
    with real scopes. The only thing wrong with it is that it was issued for a
    different service — which is precisely the token an attacker who compromised
    that service would be holding.
    """
    out = call(
        "tools/call",
        {"name": "ops.deployment_plan",
         "arguments": {"service": "checkout", "version": "1.4.2"}},
        audience=OTHER_SERVER,
    )
    assert "error" in out, "a token issued for another service was accepted"
    # The refusal names what this server DOES accept — published facts, not
    # secrets — without saying which check failed.
    assert THIS_SERVER in out["error"]["message"], out["error"]


def test_discovery_needs_no_token() -> None:
    """A client cannot discover a server it must already be authenticated to."""
    resp = httpx.post(
        BROKER,
        content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover"}),
        headers={
            "Content-Type": "application/json",
            "Mcp-Method": "server/discover",
        },
        timeout=10.0,
    )
    assert resp.status_code == 200
    assert "error" not in resp.json(), resp.json()
