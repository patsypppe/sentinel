"""MUST rules for the Streamable HTTP layer itself.

Everything else in this catalog reads the JSON-RPC envelope. These rules read
the *HTTP* one — status line, request headers, response `Content-Type` — and
they matter for the same reason the header contract matters: a gateway, a WAF,
a CDN and a retrying client all act on the HTTP layer alone, without ever
parsing a body. A server that says `-32601` inside an HTTP 200 has told the
client the call failed and told every intermediary between them that it
succeeded, and the two will not agree about what happened.
"""

from __future__ import annotations

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe

STREAMABLE = f"{SPEC_BASE}/basic/transports/streamable-http"

#: The only two response Content-Types the specification permits for a JSON-RPC
#: request: "the server MUST return either Content-Type: application/json … or
#: Content-Type: text/event-stream".
VALID_CONTENT_TYPES = ("application/json", "text/event-stream")

#: A real, previous protocol revision rather than nonsense. A server that
#: rejects the *value* as unknown rather than noticing the *disagreement* would
#: pass this rule for the wrong reason if the header carried "not-a-version";
#: 2025-11-25 is a revision a server may well support, so the only thing wrong
#: with the request is that the header and the body do not agree.
MISMATCHED_HEADER_VERSION = "2025-11-25"

#: RFC 2606 reserves `.invalid` so that it can never resolve. No allowlist a
#: server could legitimately hold contains an origin under it, which is what
#: makes serving a request from here evidence of no validation rather than
#: evidence of a permissive policy.
FOREIGN_ORIGIN = "https://sentinel-rebinding-probe.invalid"


@rule(
    id="MCP/2026-07-28/MUST/unknown-method-http-404",
    title="An unimplemented method answers 404 with -32601",
    severity=Severity.MUST,
    citation=f"{STREAMABLE}#sending-messages",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Answer a method this server does not implement with HTTP 404 Not Found AND a "
        "JSON-RPC error carrying -32601. Both, not either: the JSON-RPC code is for the "
        "client and the status line is for everything between them. A -32601 wrapped in "
        "an HTTP 200 tells a gateway, a CDN and a retry policy that the call succeeded."
    ),
    introduced_in="0.2.0",
)
def unknown_method_http_404(probe: Probe) -> RuleResult:
    response = probe.call("sentinel/definitely-not-a-real-method")
    if not response.reached_server:
        return RuleResult.indeterminate(f"unreachable: {response.transport_error}")
    if response.result() is not None:
        return RuleResult.failed(
            f"an invented method name was SERVED (HTTP {response.status})",
            evidence=str(response.result())[:300],
        )

    code = response.error_code()
    problems: list[str] = []
    if response.status != 404:
        problems.append(f"HTTP status was {response.status}, not 404")
    if code != -32601:
        problems.append(f"the JSON-RPC error code was {code}, not -32601")
    if problems:
        return RuleResult.failed(
            "an unimplemented method was refused, but not as the spec requires: "
            + "; ".join(problems),
            evidence=f"HTTP {response.status}, code {code}",
        )
    return RuleResult.passed("an unimplemented method returned HTTP 404 and -32601")


@rule(
    id="MCP/2026-07-28/MUST/protocol-version-header-required",
    title="A POST with no MCP-Protocol-Version header is rejected with -32020 and HTTP 400",
    severity=Severity.MUST,
    citation=f"{STREAMABLE}#protocol-version-header",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Require MCP-Protocol-Version on every POST and reject a request without it with "
        "HTTP 400 and a -32020 JSON-RPC error. The header exists so an intermediary can "
        "route by revision without parsing the body; if it is optional, a caller reaches "
        "whichever version the server happens to assume by simply leaving it off."
    ),
    introduced_in="0.2.0",
)
def protocol_version_header_required(probe: Probe) -> RuleResult:
    # The body still declares the version -- only the header is missing. That
    # separates this rule from missing-protocol-version-rejected, which omits
    # the _meta field as well and is answered -32602 for the absent field.
    response = probe.tools_list(omit_protocol_version_header=True)
    if not response.reached_server:
        return RuleResult.indeterminate(f"unreachable: {response.transport_error}")
    if response.result() is not None:
        return RuleResult.failed(
            f"tools/list was SERVED with no MCP-Protocol-Version header (HTTP "
            f"{response.status}); any revision-aware policy in front of this server can "
            "be bypassed by omitting the header",
            evidence=str(response.result())[:300],
        )

    code = response.error_code()
    problems: list[str] = []
    if response.status != 400:
        problems.append(f"HTTP status was {response.status}, not 400")
    if code != -32020:
        problems.append(f"the JSON-RPC error code was {code}, not -32020")
    if problems:
        return RuleResult.failed(
            "a POST with no MCP-Protocol-Version header was refused, but not as the spec "
            "requires: " + "; ".join(problems),
            evidence=f"HTTP {response.status}, code {code}",
        )
    return RuleResult.passed(
        "a POST with no MCP-Protocol-Version header was rejected with -32020 and HTTP 400"
    )


@rule(
    id="MCP/2026-07-28/MUST/protocol-version-header-body-mismatch-rejected",
    title="A protocol version header disagreeing with the body is rejected",
    severity=Severity.MUST,
    citation=f"{STREAMABLE}#protocol-version-header",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Compare MCP-Protocol-Version against _meta.io.modelcontextprotocol/"
        "protocolVersion and answer HTTP 400 with a -32020 HeaderMismatch when they "
        "disagree. This is what makes the header BINDING: a gateway that routes an old "
        "revision to an old backend has authorized a request that then ran at a "
        "different version than the one it was authorized for."
    ),
    introduced_in="0.2.0",
)
def protocol_version_header_body_mismatch_rejected(probe: Probe) -> RuleResult:
    response = probe.tools_list(protocol_version_header=MISMATCHED_HEADER_VERSION)
    if not response.reached_server:
        return RuleResult.indeterminate(f"unreachable: {response.transport_error}")
    if response.result() is not None:
        return RuleResult.failed(
            f"a request whose MCP-Protocol-Version header said "
            f"{MISMATCHED_HEADER_VERSION} while its body declared "
            f"{probe.protocol_version} was SERVED; a gateway routing on the header "
            "authorized a different revision than the one that ran",
            evidence=str(response.result())[:300],
        )

    code = response.error_code()
    problems: list[str] = []
    if response.status != 400:
        problems.append(f"HTTP status was {response.status}, not 400")
    if code != -32020:
        problems.append(f"the JSON-RPC error code was {code}, not -32020")
    if problems:
        return RuleResult.failed(
            "a header/body protocol-version mismatch was refused, but not as the spec "
            "requires: " + "; ".join(problems),
            evidence=f"HTTP {response.status}, code {code}",
        )
    return RuleResult.passed(
        "a header/body protocol-version mismatch returned -32020 and HTTP 400"
    )


@rule(
    id="MCP/2026-07-28/MUST/invalid-origin-rejected",
    title="A request from an impossible Origin is refused with HTTP 403",
    severity=Severity.MUST,
    citation=f"{STREAMABLE}#security-endpoint",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Validate the Origin header on every request and answer 403 Forbidden when it "
        "is present and not allowed. Without it a page the user visits can drive this "
        "server through the user's own browser -- which is the DNS rebinding attack the "
        "requirement exists for, and it does not care that the endpoint is internal."
    ),
    introduced_in="0.2.0",
)
def invalid_origin_rejected(probe: Probe) -> RuleResult:
    response = probe.tools_list(headers={"Origin": FOREIGN_ORIGIN})
    if not response.reached_server:
        return RuleResult.indeterminate(f"unreachable: {response.transport_error}")
    if response.status == 403:
        return RuleResult.passed(f"Origin {FOREIGN_ORIGIN} was refused with 403")
    if 200 <= response.status < 300:
        return RuleResult.failed(
            f"a request carrying Origin: {FOREIGN_ORIGIN} was SERVED (HTTP "
            f"{response.status}). .invalid can never resolve, so no allowlist "
            "contains it and no Origin check ran",
            evidence=f"HTTP {response.status}",
        )
    return RuleResult.indeterminate(
        f"the request was refused with HTTP {response.status} rather than 403; the "
        "refusal may be for another reason entirely, so this does not settle whether "
        "Origin is validated"
    )


@rule(
    id="MCP/2026-07-28/MUST/response-content-type-valid",
    title="A JSON-RPC request is answered as application/json or text/event-stream",
    severity=Severity.MUST,
    citation=f"{STREAMABLE}#sending-messages",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Label the response application/json for a single reply, or text/event-stream "
        "when streaming. Those are the only two the specification permits, and the "
        "client chooses how to read the body from this header alone -- it announced "
        "support for exactly these two in its Accept header and has no third parser."
    ),
    introduced_in="0.2.0",
)
def response_content_type_valid(probe: Probe) -> RuleResult:
    response = probe.tools_list()
    if not response.reached_server:
        return RuleResult.indeterminate(f"unreachable: {response.transport_error}")

    raw = response.headers.get("content-type")
    if raw is None:
        return RuleResult.failed(
            f"the response to tools/list carried no Content-Type header (HTTP "
            f"{response.status}); the client cannot tell a single JSON reply from a "
            "stream without one",
            evidence=f"HTTP {response.status}",
        )
    # A charset or boundary parameter is legitimate; the media type is what the
    # specification constrains.
    media_type = raw.split(";")[0].strip().lower()
    if media_type in VALID_CONTENT_TYPES:
        return RuleResult.passed(f"tools/list was answered as {media_type}")
    return RuleResult.failed(
        f"tools/list was answered as {raw!r}; the specification permits "
        f"{' or '.join(VALID_CONTENT_TYPES)} and nothing else",
        evidence=f"Content-Type: {raw}",
    )


@rule(
    id="MCP/2026-07-28/MUST/notification-not-answered-with-a-result",
    title="A notification is accepted with 202, or refused; never answered",
    severity=Severity.MUST,
    citation=f"{STREAMABLE}#sending-messages",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Answer a JSON-RPC notification with 202 Accepted and an empty body, or with an "
        "HTTP error status if you cannot accept it. A notification carries no id, so a "
        "JSON-RPC result sent back cannot be correlated with anything and the client has "
        "no way to interpret it."
    ),
    introduced_in="0.2.0",
)
def notification_not_answered_with_a_result(probe: Probe) -> RuleResult:
    # An HTTP error IS a pass here, deliberately. This revision defines no
    # client-to-server notifications over Streamable HTTP, so "the server cannot
    # accept it" is the correct state for a conformant server to be in, and the
    # specification spells out what it owes the client in that case. Demanding
    # 202 outright would fail a server for refusing something nothing sends.
    response = probe.notify("notifications/sentinel-probe")
    if not response.reached_server:
        return RuleResult.indeterminate(f"unreachable: {response.transport_error}")
    if response.status == 202:
        if response.body.strip():
            return RuleResult.failed(
                "202 Accepted carried a body; the spec says 'with no body'",
                evidence=response.body[:200].decode("utf-8", "replace"),
            )
        return RuleResult.passed("a notification was accepted with 202 and no body")
    if response.status >= 400:
        return RuleResult.passed(
            f"the notification was refused with HTTP {response.status}, which the spec "
            "permits for a notification the server cannot accept"
        )
    if response.result() is not None:
        return RuleResult.failed(
            f"a notification (no id) was answered with a JSON-RPC result and HTTP "
            f"{response.status}; the client has no id to correlate it with",
            evidence=f"HTTP {response.status}",
        )
    return RuleResult.failed(
        f"a notification was answered with HTTP {response.status}; expected 202 or an "
        "error status"
    )
