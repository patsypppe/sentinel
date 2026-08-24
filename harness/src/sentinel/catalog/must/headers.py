"""MUST rules for the header contract and error taxonomy (`SN-CAP-05`, `SN-CAP-03`)."""

from __future__ import annotations

from collections.abc import Callable

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import HEADER_MCP_METHOD, Probe
from sentinel.probe.transport import RawResponse, Request

TRANSPORT = f"{SPEC_BASE}/basic/transports"
CHANGELOG = f"{SPEC_BASE}/changelog"
ERRORS = f"{SPEC_BASE}/basic/index#error-codes"

#: Codes -32020…-32099 are reserved for the specification, and only these three
#: are defined in it.
SPEC_ALLOCATED = {-32020, -32021, -32022}


def _named_tool(probe: Probe) -> str | None:
    """The name of any tool this server advertises, or None.

    `probe.first_tool_name()` reads the first entry only, and a server whose
    first tool has no name is precisely the kind this catalog expects to meet --
    `tools-are-named` exists because such servers are real. Falling back to an
    invented name would be worse than useless here: the refusal that came back
    would be about the unknown tool, not about the missing header.
    """
    result = probe.tools_list().result()
    tools = (result or {}).get("tools")
    if not isinstance(tools, list):
        return None
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name")
        if isinstance(name, str) and name:
            return name
    return None


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
    title="Mcp-Name is required on a tools/call, resources/read or prompts/get POST",
    severity=Severity.MUST,
    citation=f"{TRANSPORT}#streamable-http",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Reject a tools/call, resources/read or prompts/get with no Mcp-Name header. "
        "Without it a gateway cannot tell one tools/call from another, so it cannot "
        "authorize a specific tool without reading the body. The header table requires "
        "Mcp-Name for those three methods only -- 'All requests' is Mcp-Method's row."
    ),
)
def mcp_name_required(probe: Probe) -> RuleResult:
    # Mcp-Name is required for tools/call, resources/read and prompts/get -- not
    # for "All requests", which is Mcp-Method's row in the table. Provoking on
    # tools/list would demand a header the specification does not require there.
    name = _named_tool(probe)
    if name is None:
        return RuleResult.indeterminate(
            "this server advertises no named tool, so there is no tools/call to omit "
            "Mcp-Name from"
        )

    resp = probe.tools_call(name, {}, omit_mcp_name=True)
    if not resp.reached_server:
        return RuleResult.indeterminate(f"the server was unreachable: {resp.transport_error}")

    if resp.result() is not None:
        return RuleResult.failed(
            f"tools/call {name!r} was served with no Mcp-Name header; a gateway "
            "authorizing one tool and not another cannot do so if the header naming "
            "the tool is optional",
            evidence=str(resp.result())[:300],
        )

    # The same call WITH the header. If that is refused identically, the refusal
    # was about the call and not about the missing header, and this rule has not
    # been settled -- an unverifiable MUST is INDETERMINATE, never a pass.
    control = probe.tools_call(name, {})
    if control.result() is None and control.error_code() == resp.error_code():
        return RuleResult.indeterminate(
            f"tools/call {name!r} is refused with {resp.error_code()} whether or not "
            f"Mcp-Name is sent, so the refusal cannot be attributed to the header: "
            f"{str(control.error())[:200]}"
        )
    return RuleResult.passed("a tools/call with no Mcp-Name was refused")


#: Methods the header table does NOT define `Mcp-Name` for. Every one of them is
#: a list-style method with neither `params.name` nor `params.uri`, so there is
#: no body value for a header to be matched against.
NO_NAME_METHODS = [
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
]


@rule(
    id="MCP/2026-07-28/MUST/mcp-name-not-required-where-undefined",
    title="Mcp-Name is not demanded on a method the header table does not define it for",
    severity=Severity.MUST,
    citation=f"{TRANSPORT}#streamable-http",
    verifiability=Verifiability.BLACK_BOX,
    introduced_in="0.2.0",
    remediation=(
        "Require Mcp-Name for tools/call, resources/read and prompts/get only, and serve "
        "a list request that carries none. The header is SOURCED FROM params.name or "
        "params.uri; a method with neither has nothing for it to match, so demanding one "
        "there refuses a request that satisfies every MUST. A conformant client sends no "
        "Mcp-Name on tools/list, so a server that requires it everywhere answers -32020 to "
        "the very first call and looks broken to every client but its own."
    ),
)
def mcp_name_not_required_where_undefined(probe: Probe) -> RuleResult:
    # The probe already omits Mcp-Name on these methods, so each of these is
    # simply a conformant request. What is being asked is whether it is served.
    offenders: list[str] = []
    checked = 0

    for method in NO_NAME_METHODS:
        resp = probe.call(method)
        if not resp.reached_server:
            return RuleResult.indeterminate(f"the server was unreachable: {resp.transport_error}")
        if resp.result() is not None:
            checked += 1
            continue

        # Refused. Attributing that refusal to the missing header needs the
        # control: the SAME request carrying Mcp-Name set to the method name,
        # which is the value a server that invented an "otherwise" clause for
        # the header table would be expecting. If that one is served and this
        # one was not, the header is what decided it.
        control = probe.call(method, mcp_name=method)
        if control.result() is None:
            # Refused either way -- the method is not implemented, or the
            # refusal is about something else entirely. Not this rule's finding.
            continue
        checked += 1
        offenders.append(f"{method} (refused with {resp.error_code()})")

    if checked == 0:
        return RuleResult.indeterminate(
            "no method in the header table's non-Mcp-Name set could be settled: each was "
            "refused whether or not the header was sent, so nothing is attributable to it"
        )
    if offenders:
        return RuleResult.failed(
            f"{len(offenders)} of {checked} method(s) were refused without Mcp-Name and "
            f"served with it: {offenders}. The header table requires Mcp-Name for "
            "tools/call, resources/read and prompts/get -- 'All requests' is Mcp-Method's "
            "row -- so this server refuses conformant traffic",
            evidence=f"refused without Mcp-Name, served with it: {offenders}",
        )
    return RuleResult.passed(
        f"{checked} method(s) with no params.name or params.uri were served with no Mcp-Name"
    )


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
        "-32002 in this revision, and -32002 now sits in the retired -32000…-32019 "
        "sub-range -- the one code the revision exempts by name, precisely because so "
        "many servers still emit it for the meaning it used to have."
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
        "Move implementation-defined error codes outside the JSON-RPC reserved range "
        "(-32768 to -32000) entirely. The range -32020…-32099 is reserved for the "
        "specification, and only -32020, -32021 and -32022 are defined in it; occupying "
        "the rest means a future revision's code will collide with yours and clients will "
        "act on the wrong meaning. -32000…-32019 is not the answer either -- this revision "
        "retired that sub-range, which SHOULD/no-errors-in-legacy-range reports separately."
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
            # Mcp-Method only: tools/list has no params.name or params.uri, so
            # an Mcp-Name here would assert a body value that does not exist --
            # and against an unparseable body, nothing could match it anyway.
            headers={HEADER_MCP_METHOD: "tools/list"},
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
