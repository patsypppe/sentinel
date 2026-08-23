"""MUST rules for the header contract and error taxonomy (`SN-CAP-05`, `SN-CAP-03`)."""

from __future__ import annotations

from collections.abc import Callable

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import HEADER_MCP_METHOD, HEADER_MCP_NAME, Probe
from sentinel.probe.transport import RawResponse, Request

TRANSPORT = f"{SPEC_BASE}/basic/transports"
CHANGELOG = f"{SPEC_BASE}/changelog"
ERRORS = f"{SPEC_BASE}/basic/index#error-codes"

#: Codes -32020…-32099 are reserved for the specification, and only these three
#: are defined in it.
SPEC_ALLOCATED = {-32020, -32021, -32022}


@rule(
    id="MCP/2026-07-28/MUST/mcp-method-header-required",
    title="Mcp-Method is required on Streamable HTTP POST",
    severity=Severity.MUST,
    citation=f"{TRANSPORT}#streamable-http",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Reject a POST with no Mcp-Method header. The header exists so a gateway or WAF "
        "can route and authorize WITHOUT parsing the JSON body; serving a request that "
        "lacks it means any header-based policy in front of this server can be bypassed "
        "by simply omitting the header."
    ),
)
def mcp_method_required(probe: Probe) -> RuleResult:
    resp = probe.tools_list(omit_mcp_method=True)
    if not resp.reached_server:
        return RuleResult.indeterminate(f"the server was unreachable: {resp.transport_error}")

    if resp.result() is not None:
        return RuleResult.failed(
            "tools/list was served with no Mcp-Method header; a header-based gateway "
            "policy in front of this server can be bypassed by omitting the header",
            evidence=str(resp.result())[:300],
        )
    if resp.status >= 400:
        return RuleResult.passed(f"a request with no Mcp-Method was refused (HTTP {resp.status})")
    return RuleResult.passed(f"a request with no Mcp-Method was refused (code {resp.error_code()})")


@rule(
    id="MCP/2026-07-28/MUST/mcp-name-header-required",
    title="Mcp-Name is required on Streamable HTTP POST",
    severity=Severity.MUST,
    citation=f"{TRANSPORT}#streamable-http",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Reject a POST with no Mcp-Name header. Without it a gateway cannot tell one "
        "tools/call from another, so it cannot authorize a specific tool without reading "
        "the body."
    ),
)
def mcp_name_required(probe: Probe) -> RuleResult:
    resp = probe.tools_list(omit_mcp_name=True)
    if not resp.reached_server:
        return RuleResult.indeterminate(f"the server was unreachable: {resp.transport_error}")

    if resp.result() is not None:
        return RuleResult.failed(
            "tools/list was served with no Mcp-Name header",
            evidence=str(resp.result())[:300],
        )
    return RuleResult.passed("a request with no Mcp-Name was refused")


@rule(
    id="MCP/2026-07-28/MUST/header-body-mismatch-rejected",
    title="A header disagreeing with the body is rejected with -32020",
    severity=Severity.MUST,
    citation=f"{TRANSPORT}#header-contract",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Compare Mcp-Method and Mcp-Name against the JSON-RPC body and return -32020 "
        "HeaderMismatch when they disagree. This is what makes the headers BINDING: a "
        "gateway routes on them, so a body that says something else must not be honoured, "
        "or the gateway's decision was about a request that never happened."
    ),
)
def header_mismatch_rejected(probe: Probe) -> RuleResult:
    # The header claims tools/list; the body calls tools/call. This is the exact
    # shape of a request trying to slip past a header-based policy.
    resp = probe.tools_call(
        "any.tool", {}, mcp_method="tools/list", mcp_name="tools/list"
    )
    if not resp.reached_server:
        return RuleResult.indeterminate(f"the server was unreachable: {resp.transport_error}")

    code = resp.error_code()
    if code == -32020:
        return RuleResult.passed("a header/body mismatch returned -32020")
    if resp.result() is not None:
        return RuleResult.failed(
            "a request whose Mcp-Method header said tools/list while its body called "
            "tools/call was SERVED; a gateway routing on the header authorized a "
            "different request than the one that ran",
            evidence=str(resp.result())[:300],
        )
    return RuleResult.failed(
        f"a header/body mismatch returned {code} rather than -32020",
        evidence=str(resp.error()),
    )


@rule(
    id="MCP/2026-07-28/MUST/resource-not-found-is-invalid-params",
    title="Resource not found is -32602, not -32002",
    severity=Severity.MUST,
    citation=f"{CHANGELOG}#error-code-reallocation",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Return -32602 InvalidParams for a resource that does not exist. It moved from "
        "-32002 in this revision, and -32002 now falls in the implementation-defined range "
        "where it means whatever the server chose."
    ),
)
def resource_not_found_code(probe: Probe) -> RuleResult:
    resp = probe.resources_read("sentinel://does-not-exist/probe")
    if not resp.reached_server:
        return RuleResult.indeterminate(f"the server was unreachable: {resp.transport_error}")

    code = resp.error_code()
    if code == -32601:
        return RuleResult.not_applicable("this server does not implement resources/read")
    if code == -32602:
        return RuleResult.passed("an unknown resource returned -32602")
    if code == -32002:
        return RuleResult.failed(
            "an unknown resource returned -32002, which was the code BEFORE this revision; "
            "it is now -32602",
            evidence=str(resp.error()),
        )
    if resp.result() is not None:
        return RuleResult.failed(
            "reading a resource that does not exist returned a result",
            evidence=str(resp.result())[:300],
        )
    return RuleResult.failed(f"an unknown resource returned {code} rather than -32602")


@rule(
    id="MCP/2026-07-28/MUST/no-errors-in-reserved-range",
    title="No error code falls in the specification's reserved range",
    severity=Severity.MUST,
    citation=f"{ERRORS}",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Move implementation-defined error codes into -32000…-32019. The range "
        "-32020…-32099 is reserved for the specification, and only -32020, -32021 and "
        "-32022 are defined in it; occupying the rest means a future revision's code will "
        "collide with yours and clients will act on the wrong meaning."
    ),
)
def no_reserved_range_errors(probe: Probe) -> RuleResult:
    # Provoke as many distinct errors as the wire allows, and look at every code
    # that comes back.
    provocations: list[tuple[str, Callable[[], RawResponse]]] = [
        ("unknown method", lambda: probe.call("sentinel/no-such-method", {})),
        ("unsupported version", lambda: probe.tools_list(version="2099-01-01")),
        ("header mismatch", lambda: probe.tools_call("x", {}, mcp_method="tools/list")),
        ("unknown tool", lambda: probe.tools_call("sentinel.no-such-tool", {})),
        ("unknown resource", lambda: probe.resources_read("sentinel://nope")),
        ("removed method", lambda: probe.call("ping", {})),
        ("bad params", lambda: probe.call("tools/call", {"nonsense": True})),
    ]

    offenders: list[str] = []
    seen: list[int] = []

    for label, send in provocations:
        resp = send()
        code = resp.error_code()
        if code is None:
            continue
        seen.append(code)
        if -32099 <= code <= -32020 and code not in SPEC_ALLOCATED:
            offenders.append(f"{label} → {code}")

    if not seen:
        return RuleResult.indeterminate("no error codes could be provoked from this server")
    if offenders:
        return RuleResult.failed(
            f"error code(s) allocated inside the reserved range -32020…-32099: {offenders}",
            evidence=f"codes observed: {sorted(set(seen))}",
        )
    return RuleResult.passed(
        f"{len(set(seen))} distinct error codes observed, none in the reserved range"
    )


@rule(
    id="MCP/2026-07-28/MUST/unknown-method-is-method-not-found",
    title="An unknown method returns -32601",
    severity=Severity.MUST,
    citation=f"{ERRORS}",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Return -32601 MethodNotFound for a method this server does not implement, as a "
        "JSON-RPC error rather than an HTTP 404. A client cannot distinguish a missing "
        "method from a missing endpoint or a proxy error otherwise."
    ),
)
def unknown_method(probe: Probe) -> RuleResult:
    resp = probe.call("sentinel/definitely-not-a-real-method", {})
    if not resp.reached_server:
        return RuleResult.indeterminate(f"the server was unreachable: {resp.transport_error}")

    if resp.result() is not None:
        return RuleResult.failed(
            "an invented method name was SERVED", evidence=str(resp.result())[:300]
        )
    code = resp.error_code()
    if code == -32601:
        return RuleResult.passed("an unknown method returns -32601")
    if code is None:
        return RuleResult.failed(
            f"an unknown method produced no JSON-RPC error (HTTP {resp.status})",
            evidence=resp.body[:300].decode(errors="replace"),
        )
    return RuleResult.failed(f"an unknown method returned {code} rather than -32601")


@rule(
    id="MCP/2026-07-28/MUST/malformed-json-is-parse-error",
    title="Malformed JSON returns -32700",
    severity=Severity.MUST,
    citation=f"{ERRORS}",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Return -32700 ParseError for a body that is not valid JSON. Closing the "
        "connection or returning a bare HTTP error leaves the client unable to tell a "
        "malformed request from a network fault, and it will retry the former forever."
    ),
)
def malformed_json(probe: Probe) -> RuleResult:
    resp = probe.send(
        Request(
            method="tools/list",
            raw_body=b'{"jsonrpc":"2.0","id":1,"method":',
            headers={HEADER_MCP_METHOD: "tools/list", HEADER_MCP_NAME: "tools/list"},
        )
    )
    if not resp.reached_server:
        return RuleResult.indeterminate(f"the server was unreachable: {resp.transport_error}")

    code = resp.error_code()
    if code == -32700:
        return RuleResult.passed("malformed JSON returns -32700")
    if code is not None:
        return RuleResult.failed(f"malformed JSON returned {code} rather than -32700")
    return RuleResult.failed(
        f"malformed JSON produced no JSON-RPC error (HTTP {resp.status})",
        evidence=resp.body[:300].decode(errors="replace"),
    )
