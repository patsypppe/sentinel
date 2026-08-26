"""A minimal, correct MCP 2026-07-28 server.

`docs/HANDOFF.md` §9.5: the false-positive half of the harness's oracle. It must
trip ZERO rules.

It is written to be *minimal* rather than impressive — no database, no tools
that do anything, no state at all. That is the point: it establishes that the
rules constrain PROTOCOL BEHAVIOUR and not implementation choices. A rule that
fails here is a rule demanding something the specification does not, and the
false-positive count is how that gets noticed.
"""

from __future__ import annotations

import sys
from typing import Any

from .common import (
    KEY_PROTOCOL_VERSION,
    KEY_SERVER_INFO,
    PROTOCOL,
    error,
    parse,
    result,
    serve_forever,
)

PORT = 9001

SERVER_INFO = {"name": "sentinel-conformant-fixture", "version": "0.1.0"}

#: The HTTP-layer answers `dispatch` cannot give, because they are decided
#: before or outside a JSON-RPC body. Both are `common`'s defaults and are
#: restated here so that the conformant fixture's answer to "what Content-Type,
#: and what does a bare GET get" is visible in the file a reader is auditing.
BEHAVIOUR: dict[str, Any] = {
    "response_content_type": "application/json",
    "bare_method_status": 405,
}

#: The origins this server will accept a browser request from.
#:
#: A server with no browser clients at all would hold an EMPTY allowlist and
#: refuse any request carrying an Origin whatsoever. This one holds the loopback
#: pair a local development client would use, on purpose: a fixture that refused
#: every Origin would satisfy `invalid-origin-rejected` without ever making an
#: allowlist DECISION, and "this server hates the header" and "this server
#: validates the header" would look identical from the wire.
ALLOWED_ORIGINS = frozenset({"http://localhost:3000", "http://127.0.0.1:3000"})

#: Sorted by name, byte-wise, and built once. Both properties are what
#: `tools-list-is-deterministic` and `tools-sorted-by-name` are about, and the
#: cheapest way to have them is to not construct the list per request.
TOOLS: list[dict[str, Any]] = sorted(
    [
        {
            "name": "echo.reverse",
            "description": "Return the given text, reversed.",
            "inputSchema": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
        },
        {
            "name": "echo.upper",
            "description": "Return the given text in upper case.",
            "inputSchema": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
        },
    ],
    key=lambda t: str(t["name"]).encode(),
)

#: Methods this revision removed. Present in the router so they can be REFUSED:
#: §9.1 requires method-not-found rather than silent absence, so that a
#: migrating client is told what happened rather than left guessing.
REMOVED = {
    "initialize": "server/discover",
    "ping": "",
    "logging/setLevel": "_meta.io.modelcontextprotocol/logLevel",
    "notifications/roots/list_changed": "",
    "resources/subscribe": "subscriptions/listen",
    "resources/unsubscribe": "subscriptions/listen",
    "sampling/createMessage": "multi round-trip requests",
    "roots/list": "",
}

#: Methods that carry a name in params, and which field carries it (§8.2).
NAME_BEARING = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}

#: Methods that need no principal, and therefore no negotiated version beyond
#: what negotiation itself requires.
NO_VERSION_REQUIRED = {"server/discover"}

#: The other `_meta` field this revision grades Required: Yes on every request.
#: Spelled out here rather than imported from the harness, for the reason §9.5
#: gives: a fixture that shared the harness's spelling could never contradict it.
KEY_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"


def cacheable(payload: dict[str, Any], *, ttl_ms: int, scope: str) -> dict[str, Any]:
    """Every list and read result is a CacheableResult."""
    return {**payload, "ttlMs": ttl_ms, "cacheScope": scope}


def enveloped(payload: dict[str, Any], version: str) -> dict[str, Any]:
    """Attach resultType and serverInfo, in one place.

    Doing it here rather than at each return is the same discipline §9.1 asks of
    a real server: a handler that builds its own envelope eventually forgets a
    field.
    """
    return {
        "resultType": "complete",
        **payload,
        "_meta": {KEY_SERVER_INFO: SERVER_INFO, KEY_PROTOCOL_VERSION: version},
    }


def declared_meta(payload: dict[str, Any]) -> dict[str, Any]:
    """The request's `_meta`, or an empty one.

    An absent `_meta` and an empty one are the same thing to a presence check,
    so they are collapsed here rather than at each caller.
    """
    params = payload.get("params")
    if not isinstance(params, dict):
        return {}
    meta = params.get("_meta")
    return meta if isinstance(meta, dict) else {}


def declared_version(payload: dict[str, Any]) -> str | None:
    version = declared_meta(payload).get(KEY_PROTOCOL_VERSION)
    return version if isinstance(version, str) else None


def expected_name(method: str, params: dict[str, Any]) -> str | None:
    """The value `Mcp-Name` must carry, for a method the header table defines it
    for. `None` means the body has no such field, so nothing can match."""
    field = NAME_BEARING[method]
    value = params.get(field)
    return str(value) if value is not None else None


def dispatch(handler: Any, body: bytes) -> tuple[int, dict[str, Any] | None]:
    # 0. Origin, before anything else is read. "Servers MUST validate the Origin
    #    header on all incoming connections to prevent DNS rebinding attacks",
    #    and the answer is 403 Forbidden. It comes first because the point of
    #    the check is that a page in someone's browser never gets to reach the
    #    body-handling code at all.
    origin = handler.headers.get("Origin")
    if origin is not None and origin not in ALLOWED_ORIGINS:
        return 403, error(None, -32600, f"Origin {origin!r} is not allowed")

    payload = parse(body)
    if payload is None:
        # -32700, as a JSON-RPC error rather than a bare HTTP status, so the
        # client can tell a malformed request from a network fault. This is
        # deliberately ahead of the header checks below: a header is validated
        # AGAINST the body, and there is no body here to validate it against.
        return 200, error(None, -32700, "request body is not valid JSON")

    # A notification carries no id -- not a null id, no id at all. There is
    # nothing for a result or an error to be correlated with, so the only
    # answers available are 202 Accepted with an empty body and an HTTP error
    # status. This revision defines no client-to-server notifications over
    # Streamable HTTP, so accepting is as defensible as refusing; accepting is
    # chosen because it exercises the harder half of the requirement.
    if "id" not in payload:
        return 202, None

    request_id = payload.get("id")
    method = payload.get("method")
    if not isinstance(method, str) or not method:
        return 200, error(request_id, -32600, "method is required")

    params = payload.get("params")
    params = params if isinstance(params, dict) else {}

    # 1. The header contract, validated against the body. -32020 on any
    #    disagreement, so a gateway routing on the headers and this server
    #    acting on the body cannot disagree about what happened.
    #
    #    Every one of these answers HTTP 400 alongside the code. A missing or
    #    disagreeing required header is a validation failure, and "servers MUST
    #    return HTTP status 400 Bad Request and MUST include a JSON-RPC error
    #    response" -- both, because the gateway whose routing decision was
    #    bypassed is exactly the component that reads only the status line.
    header_method = handler.headers.get("Mcp-Method")
    header_name = handler.headers.get("Mcp-Name")
    if header_method is None:
        return 400, error(request_id, -32020, "Mcp-Method is required on Streamable HTTP POST")
    if header_method != method:
        return 400, error(
            request_id, -32020,
            f"Mcp-Method is {header_method!r} but the body says {method!r}",
        )
    # Mcp-Name is required for the three methods the header table names, and
    # DEFINED for those three alone -- "All requests" is Mcp-Method's row. A
    # method with no params.name or params.uri has no body value for the header
    # to match, so one sent there asserts something that does not exist, and one
    # DEMANDED there refuses a request that satisfies every MUST.
    if method in NAME_BEARING:
        if header_name is None:
            return 400, error(
                request_id, -32020, f"Mcp-Name is required on a {method} POST"
            )
        want_name = expected_name(method, params)
        if header_name != want_name:
            return 400, error(
                request_id, -32020,
                f"Mcp-Name is {header_name!r} but the body names {want_name!r}",
            )
    elif header_name is not None:
        return 400, error(
            request_id, -32020,
            f"Mcp-Name is {header_name!r} but {method} carries no params.name or "
            "params.uri for it to match",
        )

    # 2. The per-request `_meta`. Both fields below are Required: Yes on every
    #    request, and "a request missing any required field is malformed": the
    #    answer is -32602 AND HTTP 400, not one or the other. A 200 carrying an
    #    error would leave every intermediary that only reads the status line
    #    believing the call succeeded.
    meta = declared_meta(payload)
    if KEY_CLIENT_CAPABILITIES not in meta:
        return 400, error(
            request_id, -32602,
            f"_meta.{KEY_CLIENT_CAPABILITIES} is required on every request",
        )
    # server/discover is exempt, and only from the version. Its whole purpose is
    # to tell a client which versions exist, so demanding one in order to ask
    # makes the server undiscoverable to any client that has not already
    # guessed right. Nothing exempts it from declaring capabilities.
    if method not in NO_VERSION_REQUIRED and KEY_PROTOCOL_VERSION not in meta:
        return 400, error(
            request_id, -32602,
            f"_meta.{KEY_PROTOCOL_VERSION} is required on every request; "
            "this revision has no handshake to carry it",
        )

    # 3. The MCP-Protocol-Version header. Required on every POST, and its value
    #    MUST match the version the body's `_meta` declares; a disagreement is a
    #    HeaderMismatch, which is -32020 and HTTP 400.
    #
    #    It is checked AFTER `_meta` above, deliberately. A request that declares
    #    no version in its body has no version for the header to mirror, and the
    #    defect a reader needs told about is the missing required field, not the
    #    missing header that could only have restated it. Checking the header
    #    first would answer -32020 to a request whose real problem is -32602.
    #
    #    server/discover is exempt from the header for the same reason it is
    #    exempt from the field: a client that does not yet know which versions
    #    exist cannot name one in order to ask.
    header_version = handler.headers.get("MCP-Protocol-Version")
    if method not in NO_VERSION_REQUIRED:
        if header_version is None:
            return 400, error(
                request_id, -32020,
                "the MCP-Protocol-Version header is required on every POST",
            )
        declared = meta.get(KEY_PROTOCOL_VERSION)
        if header_version != declared:
            return 400, error(
                request_id, -32020,
                f"MCP-Protocol-Version is {header_version!r} but the body declares "
                f"{declared!r}",
            )

    # 4. Negotiation, on every request — there is no handshake to fall back on.
    version = declared_version(payload)
    if method not in NO_VERSION_REQUIRED and version is not None and version != PROTOCOL:
        return 200, error(
            request_id, -32022, f"unsupported protocol version {version!r}",
            {"supportedVersions": [PROTOCOL]},
        )
    resolved = version if version == PROTOCOL else PROTOCOL

    # 5. Removed methods answer, rather than being silently absent.
    #
    #    HTTP 404 alongside the -32601, like any other method this server does
    #    not implement: "If the server does not implement the requested RPC
    #    method, it MUST respond with 404 Not Found and a JSON-RPC error with
    #    code -32601." A method that used to exist is still one that does not.
    if method in REMOVED:
        replacement = REMOVED[method]
        message = f"method {method!r} was removed in {PROTOCOL}"
        if replacement:
            message += f"; use {replacement} instead"
        return 404, error(request_id, -32601, message, {"removedIn": PROTOCOL})

    if method == "server/discover":
        return 200, result(request_id, enveloped(cacheable({
            "serverInfo": SERVER_INFO,
            "supportedVersions": [PROTOCOL],
            "capabilities": {
                # False, and true. subscriptions/listen is not implemented, so
                # claiming otherwise would make this fixture fail the very rule
                # it exists to pass.
                "tools": {"listChanged": False},
                "resources": {"listChanged": False, "subscribe": False},
                "prompts": {"listChanged": False},
            },
            "extensions": [],
        }, ttl_ms=600_000, scope="public"), resolved))

    if method == "tools/list":
        return 200, result(request_id, enveloped(cacheable(
            {"tools": TOOLS},
            # private: a server whose tool set varies by caller must not let a
            # shared intermediary reuse one caller's list for another. This one
            # does not vary, but private is the safe default and the cost of
            # being wrong in the other direction is a cross-tenant disclosure.
            ttl_ms=300_000, scope="private",
        ), resolved))

    if method == "resources/list":
        return 200, result(request_id, enveloped(cacheable(
            {"resources": []}, ttl_ms=300_000, scope="private"), resolved))

    if method == "resources/templates/list":
        return 200, result(request_id, enveloped(cacheable(
            {"resourceTemplates": []}, ttl_ms=300_000, scope="private"), resolved))

    if method == "prompts/list":
        return 200, result(request_id, enveloped(cacheable(
            {"prompts": []}, ttl_ms=300_000, scope="private"), resolved))

    if method == "resources/read":
        uri = params.get("uri")
        if not uri:
            return 200, error(request_id, -32602, '"uri" is required')
        # -32602, not -32002. Resource-not-found moved in this revision.
        return 200, error(request_id, -32602, f"resource not found: {uri!r}")

    if method == "tools/call":
        name = params.get("name")
        tool = next((t for t in TOOLS if t["name"] == name), None)
        if tool is None:
            return 200, error(
                request_id, -32602,
                f"no such tool {name!r}; call tools/list for the current manifest",
            )
        text = str((params.get("arguments") or {}).get("text", ""))
        output = text[::-1] if name == "echo.reverse" else text.upper()
        return 200, result(request_id, enveloped(
            {"content": [{"type": "text", "text": output}]}, resolved))

    # Implementation-defined codes would go outside the JSON-RPC reserved range
    # entirely (this revision retired -32000…-32019 along with reserving
    # -32020…-32099); this is a plain method-not-found, which is -32601 and,
    # on the HTTP layer, 404 Not Found.
    return 404, error(request_id, -32601, f"unknown method {method!r}")


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    serve_forever(dispatch, port, banner="conformant fixture", **BEHAVIOUR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
