"""The evidence-backed checks for the five UNVERIFIABLE MUSTs.

Each function here is attached to its rule with `rule.graybox(kind)` and runs only
when the operator supplied that kind of evidence. Each returns PASS or FAIL only
when the evidence actually settles it, and INDETERMINATE -- with the reason -- when
it does not, because "the evidence was not conclusive" is a different statement from
"the server is fine".
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from sentinel.catalog.base import RuleResult
from sentinel.graybox import Evidence
from sentinel.probe.client import Probe
from sentinel.probe.transport import RawResponse

__all__ = [
    "audience_check",
    "audit_check",
    "egress_check",
    "handle_check",
    "idempotency_check",
]

_INTEGER = re.compile(r"-?\d+")


def served(response: RawResponse) -> bool:
    """The request was answered with a result, not refused and not an error."""
    if not response.reached_server or response.status >= 400:
        return False
    result = response.result()
    return result is not None and result.get("isError") is not True


def _why_not_reached(response: RawResponse) -> str:
    return response.transport_error or f"HTTP {response.status}"


def refusal_signature(response: RawResponse) -> tuple[Any, ...]:
    """How a server says no: status, challenge, code, message. Never the body's
    free text beyond the message, and never anything the request could echo."""
    error = response.error() or {}
    return (
        response.status,
        response.headers.get("www-authenticate", ""),
        response.error_code(),
        error.get("message"),
    )


def dotted(value: Any, path: str) -> Any:
    """`structuredContent.handle` -> value['structuredContent']['handle']."""
    for part in path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return None
    return value


def last_integer(text: str) -> int | None:
    found = _INTEGER.findall(text)
    return int(found[-1]) if found else None


def _read_counter(evidence: Evidence, key: str) -> tuple[int | None, str]:
    try:
        result = evidence.run(key)
    except PermissionError as exc:
        return None, str(exc)
    if result.timed_out or result.returncode == -1:
        return None, f"{key} could not run: {result.stderr.strip()}"
    if not result.ok:
        return None, f"{key} exited {result.returncode}: {result.stderr.strip()[:200]}"
    count = last_integer(result.stdout)
    if count is None:
        return None, f"{key} printed no integer: {result.stdout.strip()[:100]!r}"
    return count, ""


# ---------------------------------------------------------------- audience


def audience_check(probe: Probe, evidence: Evidence) -> RuleResult:
    wrong = evidence.token("wrong_audience_token_env")
    assert wrong is not None  # status() == "ready" guarantees it
    control = "sentinel-control-" + uuid.uuid4().hex
    with probe.with_token(control) as bad:
        garbage = bad.tools_list()
    if not garbage.reached_server:
        return RuleResult.indeterminate(f"unreachable: {_why_not_reached(garbage)}")
    if served(garbage):
        return RuleResult.indeterminate(
            "the server answered a request carrying a garbage token, so it is not "
            "validating tokens at all and the audience check cannot be told apart from "
            "its absence"
        )
    with probe.with_token(wrong) as other:
        reply = other.tools_list()
    if not reply.reached_server:
        return RuleResult.indeterminate(f"unreachable: {_why_not_reached(reply)}")
    if served(reply):
        return RuleResult.failed(
            "the server answered a request carrying a token issued for a different "
            "audience. A token not issued for this server was accepted.",
            evidence=f"HTTP {reply.status}, result served",
        )
    if refusal_signature(reply) == refusal_signature(garbage):
        return RuleResult.indeterminate(
            "the wrong-audience token was refused, but in exactly the way a garbage token "
            "is refused, so the refusal may be the signature check and not the audience "
            "check. Indistinguishable is not the same as correct."
        )
    return RuleResult.passed(
        "the wrong-audience token was refused in a way that differs from how a garbage "
        f"token is refused (HTTP {reply.status} versus {garbage.status})"
    )


# ------------------------------------------------------------------ handle


def handle_check(probe: Probe, evidence: Evidence) -> RuleResult:
    spec = evidence.section("handle")
    for needed in ("mint_tool", "handle_field", "use_tool", "use_argument"):
        if not isinstance(spec.get(needed), str):
            return RuleResult.indeterminate(f"[graybox.handle] {needed} is not set")
    second = evidence.token("second_principal_token_env")
    assert second is not None

    minted = probe.tools_call(spec["mint_tool"], dict(spec.get("mint_arguments", {})))
    if not served(minted):
        return RuleResult.indeterminate(
            f"the first principal could not mint a handle with {spec['mint_tool']}: "
            f"{_why_not_reached(minted)}"
        )
    handle = dotted(minted.result(), spec["handle_field"])
    if not isinstance(handle, str) or not handle:
        return RuleResult.indeterminate(
            f"no handle at {spec['handle_field']!r} in the {spec['mint_tool']} result"
        )

    arguments = {**dict(spec.get("use_arguments", {})), spec["use_argument"]: handle}
    owner = probe.tools_call(spec["use_tool"], arguments)
    if not served(owner):
        return RuleResult.indeterminate(
            "the principal that minted the handle could not use it either, so a refusal "
            "for the second principal would prove nothing"
        )
    with probe.with_token(second) as intruder:
        stolen = intruder.tools_call(spec["use_tool"], arguments)
    if not stolen.reached_server and "safe mode" not in (stolen.transport_error or ""):
        return RuleResult.indeterminate(f"unreachable: {_why_not_reached(stolen)}")
    if served(stolen):
        return RuleResult.failed(
            "a handle minted by one principal was accepted from another. Possession of "
            "the handle was treated as authentication.",
            evidence=f"{spec['use_tool']} served the second principal, HTTP {stolen.status}",
        )
    return RuleResult.passed("a handle minted by one principal was refused to another")


# ------------------------------------------------------------------ egress


def egress_check(probe: Probe, evidence: Evidence) -> RuleResult:
    token = evidence.token("egress_token_env")
    tool = evidence.config.get("egress_tool")
    assert token is not None
    if not isinstance(tool, str):
        return RuleResult.indeterminate("[graybox] egress_tool is not set")
    arguments = evidence.section("egress_arguments")
    with probe.with_token(token) as caller:
        reply = caller.tools_call(tool, arguments)
    if not served(reply):
        return RuleResult.indeterminate(
            f"the authenticated call to {tool} was not served: {_why_not_reached(reply)}"
        )
    try:
        captured = evidence.run("egress_capture")
    except PermissionError as exc:
        return RuleResult.indeterminate(str(exc))
    if not captured.ok:
        return RuleResult.indeterminate(
            f"egress_capture failed ({captured.returncode}): {captured.stderr.strip()[:200]}"
        )
    if not captured.stdout.strip():
        return RuleResult.indeterminate(
            "the egress capture is empty, so the absence of the token from it proves "
            "nothing: either nothing left the server or the capture missed the window"
        )
    if token in captured.stdout:
        return RuleResult.failed(
            "the caller's token appears in the server's outbound traffic. The inbound "
            "token was forwarded downstream.",
            evidence=f"found in {len(captured.stdout)} bytes of egress capture",
        )
    return RuleResult.passed(
        "the caller's token does not appear in the egress captured while it was in use"
    )


# ------------------------------------------------------------- idempotency


def idempotency_check(probe: Probe, evidence: Evidence) -> RuleResult:
    spec = evidence.section("mrtr")
    tool = spec.get("tool")
    if not isinstance(tool, str):
        return RuleResult.indeterminate("[graybox.mrtr] tool is not set")
    arguments = dict(spec.get("arguments", {}))
    declared: dict[str, object] = {"elicitation": {}}

    before, why = _read_counter(evidence, "effect_counter")
    if before is None:
        return RuleResult.indeterminate(why)
    first = probe.tools_call(tool, arguments, client_capabilities=declared)
    result = first.result() if first.reached_server else None
    state = result.get("requestState") if result else None
    if not isinstance(state, str) or (result or {}).get("resultType") != "input_required":
        return RuleResult.indeterminate(
            f"{tool} did not answer with input_required and a requestState, so there is "
            "no flow to retry"
        )
    retry = {"requestState": state, "inputResponses": dict(spec.get("input_responses", {}))}
    completed = probe.tools_call(tool, arguments, extra_params=retry, client_capabilities=declared)
    if not served(completed):
        return RuleResult.indeterminate("the flow did not complete, so there is nothing to replay")
    after_one, why = _read_counter(evidence, "effect_counter")
    if after_one is None:
        return RuleResult.indeterminate(why)

    duplicate = probe.tools_call(tool, arguments, extra_params=retry, client_capabilities=declared)
    if not duplicate.reached_server:
        return RuleResult.indeterminate(f"unreachable on the replay: {_why_not_reached(duplicate)}")
    after_two, why = _read_counter(evidence, "effect_counter")
    if after_two is None:
        return RuleResult.indeterminate(why)

    if after_two > after_one:
        return RuleResult.failed(
            f"a duplicate retry of a consumed flow performed the effect again: the counter "
            f"went from {after_one} to {after_two}",
            evidence=f"counter {before} -> {after_one} -> {after_two}",
        )
    if after_one == before:
        return RuleResult.indeterminate(
            "completing the flow did not move the effect counter, so the counter is not "
            "measuring this tool's effect and the replay proves nothing"
        )
    return RuleResult.passed(
        f"the flow produced {after_one - before} counted effect(s) and the duplicate "
        "retry produced none"
    )


# ------------------------------------------------------------------- audit

#: How many invocations the audit check makes. More than one, so an off-by-one in
#: the log cannot hide as "one row, as expected".
AUDIT_INVOCATIONS = 3


def audit_check(probe: Probe, evidence: Evidence) -> RuleResult:
    tool = evidence.config.get("audit_tool")
    if not isinstance(tool, str):
        return RuleResult.indeterminate("[graybox] audit_tool is not set")
    arguments = evidence.section("audit_arguments")

    def verify() -> tuple[int | None, RuleResult | None]:
        try:
            run = evidence.run("audit_verify")
        except PermissionError as exc:
            return None, RuleResult.indeterminate(str(exc))
        if run.timed_out or run.returncode == -1:
            return None, RuleResult.indeterminate(
                f"audit_verify could not run: {run.stderr.strip()}"
            )
        if not run.ok:
            return None, RuleResult.failed(
                f"the audit verifier exited {run.returncode}: the log is not intact",
                evidence=run.stderr.strip()[:200] or run.stdout.strip()[:200],
            )
        count = last_integer(run.stdout)
        if count is None:
            return None, RuleResult.indeterminate(
                f"audit_verify printed no integer count: {run.stdout.strip()[:100]!r}"
            )
        return count, None

    before, problem = verify()
    if problem is not None:
        return problem
    assert before is not None
    for _ in range(AUDIT_INVOCATIONS):
        reply = probe.tools_call(tool, arguments)
        if not reply.reached_server:
            return RuleResult.indeterminate(f"unreachable: {_why_not_reached(reply)}")
    after, problem = verify()
    if problem is not None:
        return problem
    assert after is not None
    if after - before != AUDIT_INVOCATIONS:
        return RuleResult.failed(
            f"{AUDIT_INVOCATIONS} invocation(s) added {after - before} audit row(s)",
            evidence=f"audit count {before} -> {after}",
        )
    return RuleResult.passed(
        f"{AUDIT_INVOCATIONS} invocations added exactly {AUDIT_INVOCATIONS} audit rows and "
        "the verifier reported the log intact"
    )
