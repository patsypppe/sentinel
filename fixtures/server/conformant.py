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


def declared_version(payload: dict[str, Any]) -> str | None:
    params = payload.get("params")
    if not isinstance(params, dict):
        return None
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return None
    version = meta.get(KEY_PROTOCOL_VERSION)
    return version if isinstance(version, str) else None


def expected_name(method: str, params: dict[str, Any]) -> str:
    field = NAME_BEARING.get(method)
    if field is None:
        return method
    value = params.get(field)
    return str(value) if value is not None else method


def dispatch(handler: Any, body: bytes) -> tuple[int, dict[str, Any] | None]:
    payload = parse(body)
    if payload is None:
        # -32700, as a JSON-RPC error rather than a bare HTTP status, so the
        # client can tell a malformed request from a network fault.
        return 200, error(None, -32700, "request body is not valid JSON")

    request_id = payload.get("id")
    method = payload.get("method")
    if not isinstance(method, str) or not method:
        return 200, error(request_id, -32600, "method is required")

    params = payload.get("params")
    params = params if isinstance(params, dict) else {}

    # 1. The header contract, validated against the body. -32020 on any
    #    disagreement, so a gateway routing on the headers and this server
    #    acting on the body cannot disagree about what happened.
    header_method = handler.headers.get("Mcp-Method")
    header_name = handler.headers.get("Mcp-Name")
    if header_method is None:
        return 200, error(request_id, -32020, "Mcp-Method is required on Streamable HTTP POST")
    if header_method != method:
        return 200, error(
            request_id, -32020,
            f"Mcp-Method is {header_method!r} but the body says {method!r}",
        )
    if header_name is None:
        return 200, error(request_id, -32020, "Mcp-Name is required on Streamable HTTP POST")
    want_name = expected_name(method, params)
    if header_name != want_name:
        return 200, error(
            request_id, -32020,
            f"Mcp-Name is {header_name!r} but the body names {want_name!r}",
        )

    # 2. Negotiation, on every request — there is no handshake to fall back on.
    version = declared_version(payload)
    if method not in NO_VERSION_REQUIRED and version is not None and version != PROTOCOL:
        return 200, error(
            request_id, -32022, f"unsupported protocol version {version!r}",
            {"supportedVersions": [PROTOCOL]},
        )
    resolved = version if version == PROTOCOL else PROTOCOL

    # 3. Removed methods answer, rather than being silently absent.
    if method in REMOVED:
        replacement = REMOVED[method]
        message = f"method {method!r} was removed in {PROTOCOL}"
        if replacement:
            message += f"; use {replacement} instead"
        return 200, error(request_id, -32601, message, {"removedIn": PROTOCOL})

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

    # Implementation-defined codes would go in -32000…-32019; this is a plain
    # method-not-found, which is -32601 and outside the reserved range.
    return 200, error(request_id, -32601, f"unknown method {method!r}")


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    serve_forever(dispatch, port, banner="conformant fixture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
