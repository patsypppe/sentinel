"""SHOULD rules for the Streamable HTTP layer.

The one requirement here is graded SHOULD because the specification grades it
that way. "HTTP GET or DELETE to the MCP endpoint: respond with 405 Method Not
Allowed" appears under Backward Compatibility, introduced by "SHOULD respond as
follows" -- it is what this revision asks a server to say to a client still
speaking the 2025-11-25 transport, where GET opened the SSE stream and DELETE
ended the session. Neither exists now. A 405 tells such a client exactly that;
a 200, a 404 or a hang leaves it waiting for a stream that is never coming.
"""

from __future__ import annotations

import httpx

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe
from sentinel.probe.transport import Request

STREAMABLE = f"{SPEC_BASE}/basic/transports/streamable-http"

#: The two methods the old transport used on this endpoint, and which this
#: revision leaves with nothing to do.
LEGACY_METHODS = ("GET", "DELETE")


def _answers_legacy_initialize(probe: Probe) -> bool:
    """Whether the endpoint also serves 2025-11-25 clients (a dual-era server).

    Sent exactly as a legacy client sends it: no `_meta`, no Mcp-Method, the
    old revision in MCP-Protocol-Version. A server that completes this handshake
    has chosen to keep serving the previous transport, which the specification
    allows ("MAY implement both behaviors").
    """
    response = probe.send(
        Request(
            method="initialize",
            params={
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "sentinel-probe", "version": "0"},
            },
            request_id=1,
            headers={"MCP-Protocol-Version": "2025-11-25"},
        )
    )
    result = response.result()
    return result is not None and "protocolVersion" in result


@rule(
    id="MCP/2026-07-28/SHOULD/get-delete-405",
    title="A bare GET or DELETE on the endpoint answers 405 Method Not Allowed",
    severity=Severity.SHOULD,
    citation=f"{STREAMABLE}#backward-compatibility",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Answer 405 Method Not Allowed to a GET or a DELETE on the MCP endpoint. Both "
        "were part of the transport this revision replaced -- GET opened the SSE stream, "
        "DELETE ended the session -- so a client still sending them is an unmigrated one, "
        "and 405 is the answer that tells it so in a single round trip."
    ),
    introduced_in="0.2.0",
)
def get_delete_405(probe: Probe) -> RuleResult:
    # The 405 is what Backward Compatibility asks of "a server that supports
    # only this revision". A dual-era server still serves the previous
    # transport, where GET opened the SSE stream and DELETE ended the session,
    # so for it those methods are not dead. 0.3.0 graded the official reference
    # server -- which is dual-era -- as failing this; it is now not-applicable.
    if _answers_legacy_initialize(probe):
        return RuleResult.not_applicable(
            "the server also completes a legacy 2025-11-25 initialize, so it is dual-era; "
            "the 405 is asked only of a server that supports this revision alone"
        )

    # Sent over the probe's OWN httpx client rather than a fresh one: these are
    # bare non-POST requests, and the transport builds only POSTs. Borrowing the
    # client keeps the proxy, the TLS verification and the client certificate
    # identical to every other request in the scan, so a refusal here is about
    # the method and not about how the connection was made.
    client = probe._transport._client

    observed: list[str] = []
    offenders: list[str] = []
    for method in LEGACY_METHODS:
        try:
            response = client.request(method, probe.endpoint)
        except httpx.RequestError as exc:
            return RuleResult.indeterminate(
                f"a bare {method} to the endpoint never completed "
                f"({type(exc).__name__}: {exc}), so nothing can be concluded from it"
            )
        observed.append(f"{method} → HTTP {response.status_code}")
        if response.status_code != 405:
            offenders.append(f"{method} → HTTP {response.status_code}")

    if offenders:
        return RuleResult.failed(
            f"{', '.join(offenders)}; the specification asks for 405 Method Not Allowed "
            "so that a client still speaking the previous transport is told at once "
            "rather than waiting on a stream that no longer exists",
            evidence="; ".join(observed),
        )
    return RuleResult.passed(
        f"both legacy methods answer 405: {'; '.join(observed)}"
    )
