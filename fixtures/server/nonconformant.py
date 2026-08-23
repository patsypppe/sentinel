"""A deliberately non-conformant MCP server.

`docs/HANDOFF.md` §9.5 requires it to violate at least twenty MUSTs, with each
violation tagged with the rule ID it should trip. That tagging is not
decoration: `SEEDED_VIOLATIONS` below is the DENOMINATOR of the harness's recall
measurement, so recall is computed from what this file admits to rather than
from what the harness happens to find.

Every violation here is one a real server written against the previous revision
would have. This is not a caricature — it is what an unmigrated 2025-11-25
server looks like when a 2026-07-28 client talks to it.
"""

from __future__ import annotations

import itertools
import sys
from typing import Any

from .common import LEGACY, PROTOCOL, error, parse, result, serve_forever

PORT = 9000

#: Every MUST this fixture violates on purpose, by rule id.
#:
#: The harness's recall = |detected ∩ SEEDED| / |SEEDED|. Keeping the list here
#: rather than in the harness means the fixture states its own faults and the
#: scanner is graded against them, not against itself.
SEEDED_VIOLATIONS: list[str] = [
    "MCP/2026-07-28/MUST/discover-without-negotiated-version",
    "MCP/2026-07-28/MUST/discover-reports-supported-versions",
    "MCP/2026-07-28/MUST/discover-reports-server-info",
    "MCP/2026-07-28/MUST/list-changed-advertised-truthfully",
    "MCP/2026-07-28/MUST/result-type-present",
    "MCP/2026-07-28/MUST/server-info-echoed",
    "MCP/2026-07-28/MUST/cacheable-results-carry-ttl",
    "MCP/2026-07-28/MUST/cacheable-results-carry-scope",
    "MCP/2026-07-28/MUST/tools-list-is-deterministic",
    "MCP/2026-07-28/MUST/tools-declare-input-schema",
    "MCP/2026-07-28/MUST/tools-are-named",
    "MCP/2026-07-28/MUST/mcp-method-header-required",
    "MCP/2026-07-28/MUST/mcp-name-header-required",
    "MCP/2026-07-28/MUST/header-body-mismatch-rejected",
    "MCP/2026-07-28/MUST/resource-not-found-is-invalid-params",
    "MCP/2026-07-28/MUST/no-errors-in-reserved-range",
    "MCP/2026-07-28/MUST/unknown-method-is-method-not-found",
    "MCP/2026-07-28/MUST/malformed-json-is-parse-error",
    "MCP/2026-07-28/MUST/unsupported-version-rejected",
    "MCP/2026-07-28/MUST/initialize-removed",
    "MCP/2026-07-28/MUST/ping-removed",
    "MCP/2026-07-28/MUST/logging-set-level-removed",
    "MCP/2026-07-28/MUST/resources-subscribe-removed",
    "MCP/2026-07-28/MUST/resources-unsubscribe-removed",
    "MCP/2026-07-28/MUST/sampling-create-message-removed",
    "MCP/2026-07-28/MUST/roots-list-removed",
]

#: Deprecated features this fixture still depends on, by feature id.
#:
#: Separate from SEEDED_VIOLATIONS because a deprecated feature that still works
#: is not a MUST violation — it is a migration to plan. The deprecation
#: inventory is measured against this list the same way recall is measured
#: against the other: the fixture states what it has, and the tool is graded on
#: finding it.
SEEDED_DEPRECATIONS: list[str] = [
    "roots",
    "sampling",
    "logging",
    "http-sse",
    "oauth-dcr",
    "include-context",
]

#: Rotates the tool order on every call.
#:
#: VIOLATES MCP/2026-07-28/MUST/tools-list-is-deterministic — and it is the most
#: realistic fault in this file. No one writes this on purpose; it is what
#: happens when a manifest is built by iterating a hash map, which is the
#: default in Go, Python before 3.7, and every language whose map is a hash map.
_rotation = itertools.count()

TOOLS: list[dict[str, Any]] = [
    {
        "name": "warehouse.query",
        "description": "Run a query.",
        "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}}},
    },
    {
        # VIOLATES MCP/2026-07-28/MUST/tools-declare-input-schema
        "name": "warehouse.describe",
        "description": "Describe the schema.",
    },
    {
        # VIOLATES MCP/2026-07-28/MUST/tools-are-named
        "description": "A tool nobody can call, because it has no name.",
        "inputSchema": {"type": "object"},
    },
]


def declared_version(payload: dict[str, Any]) -> str | None:
    params = payload.get("params")
    if not isinstance(params, dict):
        return None
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return None
    version = meta.get("io.modelcontextprotocol/protocolVersion")
    return version if isinstance(version, str) else None


def dispatch(handler: Any, body: bytes) -> tuple[int, dict[str, Any] | None]:
    payload = parse(body)

    if payload is None:
        # VIOLATES MCP/2026-07-28/MUST/malformed-json-is-parse-error
        #
        # A bare HTTP 400 with no JSON-RPC error. The client cannot tell a
        # malformed request from a proxy fault and will retry it forever.
        return 400, {"detail": "bad request"}

    request_id = payload.get("id")
    method = payload.get("method", "")

    # VIOLATES MCP/2026-07-28/MUST/mcp-method-header-required
    # VIOLATES MCP/2026-07-28/MUST/mcp-name-header-required
    # VIOLATES MCP/2026-07-28/MUST/header-body-mismatch-rejected
    #
    # The headers are never read. Any gateway policy in front of this server is
    # decorative: a caller omits the header, or lies in it, and the body is
    # served regardless.

    if method == "server/discover":
        version = declared_version(payload)
        # VIOLATES MCP/2026-07-28/MUST/discover-without-negotiated-version
        #
        # The one method that must answer without a negotiated version refuses
        # to, which makes this server undiscoverable to any client that has not
        # already guessed the right version.
        if version is None or version != PROTOCOL:
            return 200, error(request_id, -32022, "declare a supported protocol version first")

        return 200, result(
            request_id,
            {
                # VIOLATES MCP/2026-07-28/MUST/result-type-present
                # VIOLATES MCP/2026-07-28/MUST/server-info-echoed
                # VIOLATES MCP/2026-07-28/MUST/discover-reports-supported-versions
                # VIOLATES MCP/2026-07-28/MUST/discover-reports-server-info
                #
                # The 2025-11-25 shape, unchanged: a single protocolVersion
                # instead of supportedVersions, no resultType, no serverInfo.
                "protocolVersion": PROTOCOL,
                # VIOLATES MCP/2026-07-28/MUST/list-changed-advertised-truthfully
                #
                # listChanged was true in 2025-11-25 and backed by
                # resources/subscribe. That method is gone, this server never
                # implemented subscriptions/listen, and the declaration was
                # never revisited — so a client waits for notifications that can
                # no longer arrive and serves a stale manifest indefinitely.
                "capabilities": {
                    "tools": {"listChanged": True},
                    "resources": {"listChanged": True, "subscribe": True},
                },
                # DEPRECATED roots — advertised as still supported.
                #
                # These two are not MUST violations: a deprecated feature that
                # still works is a migration to plan, not a defect. They are
                # here so `sentinel deprecations` has something to find, and
                # they are listed in SEEDED_DEPRECATIONS rather than in
                # SEEDED_VIOLATIONS for that reason.
                #
                # DEPRECATED http-sse
                "transports": ["http+sse", "stdio"],
                # DEPRECATED oauth-dcr
                "authorization": {
                    "registration_endpoint": "https://auth.legacy.example/register",
                    "issuer": "https://auth.legacy.example",
                },
                "instructions": "A server that was never migrated.",
            },
        )

    if method == "tools/list":
        version = declared_version(payload)
        # VIOLATES MCP/2026-07-28/MUST/unsupported-version-rejected
        #
        # Any version is accepted, including ones that do not exist. The client
        # is left believing a version was agreed.
        _ = version

        rotation = next(_rotation) % len(TOOLS)
        return 200, result(
            request_id,
            {
                # VIOLATES MCP/2026-07-28/MUST/tools-list-is-deterministic
                "tools": TOOLS[rotation:] + TOOLS[:rotation],
                # VIOLATES MCP/2026-07-28/MUST/cacheable-results-carry-ttl
                # VIOLATES MCP/2026-07-28/MUST/cacheable-results-carry-scope
                # VIOLATES MCP/2026-07-28/MUST/result-type-present
                # VIOLATES MCP/2026-07-28/MUST/server-info-echoed
            },
        )

    if method in ("resources/list", "resources/templates/list", "prompts/list"):
        key = {
            "resources/list": "resources",
            "resources/templates/list": "resourceTemplates",
            "prompts/list": "prompts",
        }[method]
        # VIOLATES the CacheableResult, resultType and serverInfo rules again.
        return 200, result(request_id, {key: []})

    if method == "resources/read":
        # VIOLATES MCP/2026-07-28/MUST/resource-not-found-is-invalid-params
        #
        # -32002 was the code before this revision; it is -32602 now.
        return 200, error(request_id, -32002, "resource not found")

    if method == "tools/call":
        params = payload.get("params") or {}
        name = params.get("name") if isinstance(params, dict) else None
        if name not in [t.get("name") for t in TOOLS]:
            # VIOLATES MCP/2026-07-28/MUST/no-errors-in-reserved-range
            #
            # -32050 sits inside -32020…-32099, which the specification reserves
            # for itself. A future revision will define it, and this server's
            # clients will act on the wrong meaning.
            return 200, error(request_id, -32050, "unknown tool")
        return 200, result(request_id, {"content": [{"type": "text", "text": "ok"}]})

    # Methods this revision REMOVED, all still served.
    if method == "initialize":
        # VIOLATES MCP/2026-07-28/MUST/initialize-removed
        return 200, result(
            request_id,
            {"protocolVersion": LEGACY, "capabilities": {}, "serverInfo": {"name": "legacy"}},
        )

    if method == "ping":
        # VIOLATES MCP/2026-07-28/MUST/ping-removed
        return 200, result(request_id, {})

    if method == "logging/setLevel":
        # VIOLATES MCP/2026-07-28/MUST/logging-set-level-removed
        return 200, result(request_id, {})

    if method == "resources/subscribe":
        # VIOLATES MCP/2026-07-28/MUST/resources-subscribe-removed
        return 200, result(request_id, {})

    if method == "resources/unsubscribe":
        # VIOLATES MCP/2026-07-28/MUST/resources-unsubscribe-removed
        return 200, result(request_id, {})

    if method == "sampling/createMessage":
        # VIOLATES MCP/2026-07-28/MUST/sampling-create-message-removed
        #
        # The server calling the client, which this revision removed outright.
        return 200, result(
            request_id,
            {"role": "assistant", "content": {"type": "text", "text": "hi"}},
        )

    if method == "roots/list":
        # VIOLATES MCP/2026-07-28/MUST/roots-list-removed
        return 200, result(request_id, {"roots": []})

    # VIOLATES MCP/2026-07-28/MUST/unknown-method-is-method-not-found
    # VIOLATES MCP/2026-07-28/MUST/no-errors-in-reserved-range
    #
    # A generic house error rather than -32601, so a client cannot tell a typo
    # from a feature it has not been granted. -32050 also sits inside the range
    # the specification reserves for itself.
    #
    # An earlier version returned a cheerful empty RESULT here instead. That was
    # also non-conformant, but it made this fixture answer every method
    # identically — which defeated the deprecation inventory's control probe and
    # made a server that implements `roots/list` indistinguishable from one that
    # answers anything. Returning an error keeps both violations and restores
    # the distinction a real unmigrated server would have.
    return 200, error(request_id, -32050, f"unrecognised method {method!r}")


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    serve_forever(
        dispatch,
        port,
        banner=f"non-conformant fixture ({len(SEEDED_VIOLATIONS)} seeded MUST violations)",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
