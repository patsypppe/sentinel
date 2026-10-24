"""MUST rules tying what a server declares to what it serves.

"Servers that support tools MUST declare the `tools` capability" and "servers that
declare the `tools` capability MUST respond to `tools/list`" are two halves of one
claim. A scan that checks only one lets a server be wrong in the other direction.
"""

from __future__ import annotations

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe

TOOLS = f"{SPEC_BASE}/server/tools"


@rule(
    id="MCP/2026-07-28/MUST/tools-capability-matches-tools-list",
    title="The tools capability is declared if and only if tools/list works",
    severity=Severity.MUST,
    citation=f"{TOOLS}#capabilities",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Declare the tools capability in server/discover exactly when the server serves "
        "tools/list. A server that serves tools but does not declare the capability is "
        "invisible to a client that checks first; one that declares it and cannot list "
        "is a promise it does not keep."
    ),
    introduced_in="0.4.0",
)
def tools_capability_matches_tools_list(probe: Probe) -> RuleResult:
    discovered = probe.discover()
    if discovered.unusable_reason() is not None:
        return RuleResult.indeterminate(f"unreachable: {discovered.unusable_reason()}")
    result = discovered.result()
    if result is None:
        return RuleResult.indeterminate("server/discover did not return a result")
    capabilities = result.get("capabilities")
    declared = isinstance(capabilities, dict) and "tools" in capabilities

    listed = probe.tools_list()
    if listed.unusable_reason() is not None:
        return RuleResult.indeterminate(f"unreachable: {listed.unusable_reason()}")
    body = listed.result()
    tools = body.get("tools") if body is not None else None
    serves = isinstance(tools, list)
    serves_some = serves and bool(tools)

    if declared and not serves:
        return RuleResult.failed(
            "the server declares the tools capability but tools/list does not return a tools array",
            evidence=f"tools/list HTTP {listed.status}, code {listed.error_code()}",
            key="declared-not-served",
        )
    if not declared and serves_some:
        return RuleResult.failed(
            "the server serves tools but does not declare the tools capability",
            evidence="server/discover capabilities has no 'tools'",
            key="served-not-declared",
        )
    if not declared and not serves_some:
        # Declares nothing and lists nothing. An empty array is not evidence that
        # the server supports tools, so there is nothing here to agree or disagree.
        return RuleResult.not_applicable("the server neither declares nor serves any tools")
    return RuleResult.passed("the tools capability and tools/list agree")
