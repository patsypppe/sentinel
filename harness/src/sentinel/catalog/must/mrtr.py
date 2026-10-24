"""MUST rules for multi round-trip requests that need no particular tool.

An MRTR flow is entered by a tool the scanner cannot know about, so these rules
look for one: each advertised tool is called with empty arguments, with and without
a declared elicitation capability, and a response whose `resultType` is
`input_required` is the thing under test. A server with no such tool gets
`NOT_APPLICABLE`, never a pass; nothing was checked.

The rules are deliberately silent about the *shape* of `inputRequests`. That is
a field a server fills for its own client, and grading its internal structure from
here would be grading a guess.

Safe mode applies: `Probe.tools_call` declines any tool not annotated read-only, so
these rules become `NOT_APPLICABLE` against a server you asked not to be invoked.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe
from sentinel.probe.transport import RawResponse

MRTR = f"{SPEC_BASE}/basic/patterns/mrtr"

#: How many tools are tried. Enough to find the one that asks, few enough that a
#: server with hundreds of tools is not called hundreds of times.
MAX_TOOLS = 25


@dataclass(frozen=True, slots=True)
class InputRequired:
    tool: str
    result: dict[str, object]

    @property
    def state(self) -> str | None:
        value = self.result.get("requestState")
        return value if isinstance(value, str) and value else None

    @property
    def has_requests(self) -> bool:
        return bool(self.result.get("inputRequests"))


def _tool_names(probe: Probe) -> list[str]:
    result = probe.tools_list().result()
    tools = result.get("tools") if result is not None else None
    if not isinstance(tools, list):
        return []
    return [t["name"] for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)][
        :MAX_TOOLS
    ]


def collect_input_required(
    probe: Probe, *, capabilities: dict[str, object] | None
) -> tuple[list[InputRequired], str]:
    """Every tool that answers an empty call with `input_required`.

    All of them, not the first: a rule about what an `input_required` result must
    carry has to look at each one, and the first one found depends on the order the
    server happens to list its tools in.
    """
    declared: dict[str, object] = {} if capabilities is None else capabilities
    found: list[InputRequired] = []
    reached = False
    for name in _tool_names(probe):
        response = probe.tools_call(name, {}, client_capabilities=declared)
        if response.unusable_reason() is not None:
            if "safe mode" in (response.transport_error or ""):
                continue
            return [], f"the server was unreachable: {response.unusable_reason()}"
        reached = True
        result = response.result()
        if result is not None and result.get("resultType") == "input_required":
            found.append(InputRequired(name, result))
    if found:
        return found, ""
    why = "no advertised tool answered an empty call with input_required"
    return [], why if reached else "no tool could be called (none, or safe mode skipped them)"


def _tampered(state: str) -> str:
    """The same state with one character changed. Never an empty or longer string,
    so the only thing wrong with it is that it fails verification."""
    last = state[-1]
    return state[:-1] + ("A" if last != "A" else "B")


def _rejected(response: RawResponse) -> bool:
    return response.error_code() is not None or response.status >= 400


@rule(
    id="MCP/2026-07-28/MUST/tampered-requeststate-rejected",
    title="A requestState altered by one character is rejected, not honoured",
    severity=Severity.MUST,
    citation=f"{MRTR}#server-requirements-basic-workflow",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Treat requestState as attacker-controlled input: seal it (an AEAD, or an HMAC "
        "over the state and the tool name), verify it on every retry, and reject a "
        "failure with -32602 before it reaches any business logic. A server that reads "
        "its own state back unverified lets a client choose which flow it resumes."
    ),
    introduced_in="0.4.0",
)
def tampered_requeststate_rejected(probe: Probe) -> RuleResult:
    flows, why = collect_input_required(probe, capabilities={"elicitation": {}})
    if not flows:
        return RuleResult.not_applicable(why)
    stateful = [f for f in flows if f.state is not None]
    if not stateful:
        return RuleResult.not_applicable(
            "no input_required result carried a requestState, so there is no state to alter"
        )
    found = stateful[0]
    assert found.state is not None
    forged = _tampered(found.state)
    retry = probe.tools_call(
        found.tool,
        {},
        extra_params={"requestState": forged, "inputResponses": {}},
        client_capabilities={"elicitation": {}},
    )
    if retry.unusable_reason() is not None:
        return RuleResult.indeterminate(f"unreachable on the retry: {retry.unusable_reason()}")
    if _rejected(retry):
        return RuleResult.passed(
            f"{found.tool} rejected a requestState altered by one character "
            f"(HTTP {retry.status}, code {retry.error_code()})"
        )
    outcome = (retry.result() or {}).get("resultType")
    if outcome == "input_required":
        # Asking again is an allowed reply to a retry with missing input, and the
        # MUST only applies when the state influences behaviour, so a fresh
        # input_required does not show that the forged state was honoured.
        return RuleResult.indeterminate(
            f"{found.tool} answered an altered requestState with a new input_required "
            "rather than an error. That may be a rejection in disguise or a state read back "
            "unverified; the wire cannot tell which."
        )
    return RuleResult.failed(
        f"{found.tool} accepted a requestState altered by one character and answered "
        f"with resultType {outcome!r}. The state is being read back without being "
        "verified.",
        evidence=f"HTTP {retry.status}, resultType {outcome!r}",
    )


@rule(
    id="MCP/2026-07-28/MUST/input-required-carries-requests-or-state",
    title="An input_required result carries inputRequests or a requestState",
    severity=Severity.MUST,
    citation=f"{MRTR}#server-requirements-basic-workflow",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Return at least one of inputRequests (what you need) or requestState (how to "
        "resume) with every input_required result. One with neither tells the client "
        "it must retry but gives it nothing to retry with."
    ),
    introduced_in="0.4.0",
)
def input_required_carries_requests_or_state(probe: Probe) -> RuleResult:
    flows, why = collect_input_required(probe, capabilities={"elicitation": {}})
    if not flows:
        return RuleResult.not_applicable(why)
    empty = [f for f in flows if f.state is None and not f.has_requests]
    if empty:
        names = sorted(f.tool for f in empty)
        return RuleResult.failed(
            f"{', '.join(names)} returned input_required with neither inputRequests nor "
            "requestState; the client has nothing to answer and nothing to resume with",
            evidence=f"keys: {sorted(empty[0].result)}",
            key=",".join(names),
        )
    return RuleResult.passed(f"{len(flows)} input_required result(s), each carrying what it needs")


@rule(
    id="MCP/2026-07-28/MUST/input-requests-respect-declared-capabilities",
    title="A client that declared no capabilities is not asked for any",
    severity=Severity.MUST,
    citation=f"{MRTR}#server-requirements-basic-workflow",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Read clientCapabilities on every request and do not return inputRequests "
        "that need a capability the client did not declare. A client that cannot "
        "elicit, sample or serve roots cannot answer, so the call never completes."
    ),
    introduced_in="0.4.0",
)
def input_requests_respect_declared_capabilities(probe: Probe) -> RuleResult:
    flows, why = collect_input_required(probe, capabilities=None)
    if not flows:
        # Nothing asked, or nothing could be asked. Neither is evidence that the
        # server respects declared capabilities, so this is not a pass.
        return RuleResult.not_applicable(why)
    asking = [f for f in flows if f.has_requests]
    if asking:
        names = sorted(f.tool for f in asking)
        return RuleResult.failed(
            f"{', '.join(names)} returned inputRequests to a client that declared "
            "clientCapabilities {}, which cannot answer any of them",
            evidence=f"keys: {sorted(asking[0].result)}",
            key=",".join(names),
        )
    return RuleResult.passed("no input_required result asked an undeclared client for input")
