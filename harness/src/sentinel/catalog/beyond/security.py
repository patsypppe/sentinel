"""Beyond-spec security checks.

These are `SENTINEL/SECURITY/*`: properties this project holds a server to that
the specification's security page does not state as requirements. They are the
rules that used to be filed under the spec namespace on the strength of a
citation that, read closely, never said what the rule claimed.
"""

from __future__ import annotations

from sentinel.catalog.base import RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe


@rule(
    id="SENTINEL/SECURITY/invocations-are-audited",
    title="Every tool invocation is recorded in an append-only log",
    severity=Severity.MUST,
    rationale=(
        "The 2026-07-28 security best-practices page has no audit-logging section, so "
        "no MUST in the specification requires this. It is still the property that "
        "lets an operator answer 'what did this agent do, and as whom' after the "
        "fact, and a server that cannot answer is hard to defend in an incident. "
        "Sentinel holds servers to it as an opinion, not as conformance."
    ),
    verifiability=Verifiability.UNVERIFIABLE,
    remediation=(
        "Write an append-only, hash-chained row for every invocation, and fail the "
        "invocation if the write fails. Enforce append-only with database grants rather "
        "than convention, so the property does not depend on every future code path "
        "remembering it."
    ),
    introduced_in="0.3.0",
)
def invocations_audited(_: Probe) -> RuleResult:
    return RuleResult.indeterminate(
        "An audit log is not exposed over MCP, and a server that claimed to keep one would "
        "be believed on its own word -- which is the opposite of what an audit is for. "
        "To settle it: read the log directly and verify its chain, e.g. with a "
        "verification command the server ships."
    )
