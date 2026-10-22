"""The rate-limit rule: opt-in, and able to pass or hold its tongue but never to fail.

"Servers MUST rate limit tool invocations" names no threshold. A server limiting at a
thousand calls a minute conforms, and so does one limiting at ten, so *not seeing* a limit
in N calls is not evidence of a violation, and a rule that failed it would be demanding a
number the specification never gives. What a scan can honestly do is look for one: if the
server throttles a burst, that is observed and it passes; if it does not within the burst,
the scan says it saw nothing, and says that is not the same as there being no limit.

It is also the one rule that deliberately floods the target, which is not something a
scanner does by default to a server it was asked to grade. So it runs only when asked
(`--probe-rate-limit N`), alone after every other rule (`exclusive`), and in safe mode
only through a tool the server has annotated read-only.
"""

from __future__ import annotations

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe, is_read_only

TOOLS = f"{SPEC_BASE}/server/tools"

#: The cap on a burst, whatever the operator asks for. A probe that can be pointed at a
#: server with an unbounded count is a denial-of-service tool.
MAX_BURST = 2_000

#: Words a throttling JSON-RPC error tends to carry, for servers that signal it in the
#: body and not with HTTP 429.
_THROTTLE_WORDS = ("rate limit", "rate-limit", "too many requests", "throttl")


def _throttled(status: int, message: str) -> bool:
    lowered = message.lower()
    return status == 429 or any(word in lowered for word in _THROTTLE_WORDS)


@rule(
    id="MCP/2026-07-28/MUST/tool-invocations-rate-limited",
    title="The server rate limits tool invocations",
    severity=Severity.MUST,
    citation=f"{TOOLS}#security-considerations",
    verifiability=Verifiability.GRAY_BOX,
    remediation=(
        "Limit tool invocations per principal and answer an excess with HTTP 429 (and a "
        "Retry-After) or a JSON-RPC error that says it is a rate limit. Without a limit, one "
        "caller, or one runaway agent loop, can exhaust whatever the tool spends."
    ),
    introduced_in="0.4.0",
    exclusive=True,
)
def tool_invocations_rate_limited(probe: Probe) -> RuleResult:
    burst = probe.context.get("rate_limit_probe")
    if not isinstance(burst, int) or burst <= 0:
        return RuleResult.indeterminate(
            "not probed. Flooding an endpoint you were asked to grade is not something a "
            "scanner does by default; pass --probe-rate-limit N to send a burst of N calls"
        )
    burst = min(burst, MAX_BURST)

    listed = probe.tools_list().result()
    tools = listed.get("tools") if listed is not None else None
    if not isinstance(tools, list) or not tools:
        return RuleResult.not_applicable("the server advertises no tools to invoke")
    candidates = [t for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)]
    # Prefer a tool that promises not to change anything; in safe mode, require one.
    read_only = [t for t in candidates if is_read_only(t)]
    if probe.safe and not read_only:
        return RuleResult.indeterminate(
            "skipped in safe mode: no advertised tool is annotated readOnlyHint=true, and "
            "a burst of calls to any other tool could do something burst-sized"
        )
    chosen = (read_only or candidates)[0]["name"]

    throttled_at: int | None = None
    for sent in range(1, burst + 1):
        response = probe.tools_call(chosen, {})
        if not response.reached_server:
            return RuleResult.indeterminate(
                f"the target stopped answering after {sent - 1} call(s): "
                f"{response.transport_error}. That may be a limit, but it is not a signal "
                "this rule can read"
            )
        error = response.error() or {}
        if _throttled(response.status, str(error.get("message", ""))):
            throttled_at = sent
            break
    if throttled_at is not None:
        return RuleResult.passed(
            f"calls to {chosen} were throttled after {throttled_at} of a {burst}-call burst"
        )
    return RuleResult.indeterminate(
        f"{burst} rapid calls to {chosen} were all served. That is not evidence the server has "
        "no limit (the specification names no threshold), only that this burst did not reach "
        "it; try a larger --probe-rate-limit against a server you own"
    )
