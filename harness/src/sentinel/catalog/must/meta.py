"""MUST rules for the per-request `_meta` protocol fields.

The revision removed the handshake, so every request carries its own protocol
version and client capabilities. A server that accepts a request without them is
inferring them from somewhere -- and the only somewhere left is the connection,
which is the state this revision removed.
"""

from __future__ import annotations

from sentinel import SPEC_REVISION
from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe
from sentinel.probe.transport import RawResponse

BASIC = f"{SPEC_BASE}/basic/index"


def _rejected_as_invalid_params(
    response: RawResponse, what: str, *, also_accept: tuple[int, ...] = ()
) -> RuleResult:
    """The shared verdict: -32602 (or a code in `also_accept`) AND HTTP 400."""
    if not response.reached_server:
        return RuleResult.indeterminate(
            f"the target was unreachable while testing {what}: {response.transport_error}"
        )
    code = response.error_code()
    if code is None:
        return RuleResult.failed(
            f"a request omitting {what} was SERVED; a required field was inferred "
            "rather than read, and the only place left to infer it from is the connection",
            evidence=f"HTTP {response.status}, no JSON-RPC error in the body",
        )
    problems: list[str] = []
    if code != -32602 and code not in also_accept:
        accepted = " or ".join(str(c) for c in (-32602, *also_accept))
        problems.append(f"error code was {code}, not {accepted}")
    if response.status != 400:
        problems.append(f"HTTP status was {response.status}, not 400")
    if problems:
        return RuleResult.failed(
            f"a request omitting {what} was rejected, but not as the spec requires: "
            + "; ".join(problems),
            evidence=f"HTTP {response.status}, code {code}",
        )
    return RuleResult.passed(f"a request omitting {what} was rejected with {code} and HTTP 400")


@rule(
    id="MCP/2026-07-28/MUST/missing-client-capabilities-rejected",
    title="A request without clientCapabilities is rejected with -32602 and HTTP 400",
    severity=Severity.MUST,
    citation=f"{BASIC}#_meta",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Reject a request whose _meta omits io.modelcontextprotocol/clientCapabilities "
        "with -32602 and HTTP 400. The field is Required: Yes, and a server that "
        "proceeds without it is guessing what the client can do -- which is how a "
        "server ends up returning an elicitation request to a client that cannot "
        "elicit, stalling the call forever."
    ),
    introduced_in="0.2.0",
)
def missing_client_capabilities_rejected(probe: Probe) -> RuleResult:
    return _rejected_as_invalid_params(
        probe.tools_list(omit_client_capabilities=True),
        "io.modelcontextprotocol/clientCapabilities",
    )


@rule(
    id="MCP/2026-07-28/MUST/missing-protocol-version-rejected",
    title="A request without a declared protocol version is rejected with -32602 and HTTP 400",
    severity=Severity.MUST,
    citation=f"{BASIC}#_meta",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Reject a request whose _meta omits io.modelcontextprotocol/protocolVersion with "
        "-32602 and HTTP 400. Serving it means the version came from somewhere other than "
        "the request, and in a protocol with no handshake there is nowhere else it can "
        "legitimately come from."
    ),
    introduced_in="0.2.0",
)
def missing_protocol_version_rejected(probe: Probe) -> RuleResult:
    # The body omits the field; the MCP-Protocol-Version header is still sent.
    #
    # 0.3.0 omitted the header too, and that request is a different one: the
    # transport lets a dual-era server treat a request with no version header as
    # a legacy client, so the official reference server answered it as legacy
    # (correctly) and this rule failed it. With the header present the request
    # is unambiguously modern and its body is missing a Required: Yes field.
    #
    # The header now names a version the body does not, so a server may also
    # see a header/body mismatch: -32020 is accepted alongside -32602, HTTP 400
    # required either way. Both are refusals the spec mandates for this request.
    return _rejected_as_invalid_params(
        probe.tools_list(version=None, protocol_version_header=SPEC_REVISION),
        "io.modelcontextprotocol/protocolVersion",
        also_accept=(-32020,),
    )


@rule(
    id="MCP/2026-07-28/MUST/missing-capability-error-shape",
    title="A -32021 error names the capabilities it needed",
    severity=Severity.MUST,
    citation=f"{BASIC}#_meta",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "When returning -32021 MissingRequiredClientCapability, populate "
        "data.requiredCapabilities with the capabilities the request needed and HTTP "
        "400. Without the list the client cannot know what to declare, so the error "
        "tells it that it failed but not how to succeed."
    ),
    introduced_in="0.2.0",
)
def missing_capability_error_shape(probe: Probe) -> RuleResult:
    # The probe declares no capabilities at all, so any operation that needs one
    # should provoke this. If nothing does, the rule does not apply -- it is not
    # a defect for a server to need no client capability.
    attempts: list[RawResponse] = [
        probe.tools_list(client_capabilities={}),
        probe.prompts_list(client_capabilities={}),
    ]
    name = probe.first_tool_name()
    if name is not None:
        attempts.append(probe.tools_call(name, {}, client_capabilities={}))

    for response in attempts:
        if response.error_code() != -32021:
            continue
        error = response.error() or {}
        data = error.get("data")
        required = data.get("requiredCapabilities") if isinstance(data, dict) else None
        problems: list[str] = []
        if not isinstance(required, list) or not required:
            problems.append(f"data.requiredCapabilities is {required!r}, not a non-empty array")
        if response.status != 400:
            problems.append(f"HTTP status was {response.status}, not 400")
        if problems:
            return RuleResult.failed(
                "a -32021 error was returned, but not in the shape the spec requires: "
                + "; ".join(problems),
                evidence=str(error)[:400],
            )
        return RuleResult.passed(f"-32021 named the capabilities it needed: {required}")

    return RuleResult.not_applicable(
        "no request the probe can make required a client capability, so -32021 was "
        "never provoked"
    )
