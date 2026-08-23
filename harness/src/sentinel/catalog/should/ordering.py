"""SHOULD rules.

These are recommendations rather than requirements, and they do not fail the
gate. They are worth reporting because each one has a concrete cost: an
unordered manifest costs cache hits, a missing description costs tool-selection
accuracy.
"""

from __future__ import annotations

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe

CHANGELOG = f"{SPEC_BASE}/changelog"


@rule(
    id="MCP/2026-07-28/SHOULD/tools-sorted-by-name",
    title="tools/list returns tools in byte-wise name order",
    severity=Severity.SHOULD,
    citation=f"{CHANGELOG}#deterministic-tool-ordering",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Sort tools by name byte-wise (not case-insensitively, not by locale collation). "
        "Any stable order satisfies the MUST, but a canonical one means two servers "
        "advertising the same tools produce the same manifest, which is what makes a "
        "manifest hash comparable across deployments."
    ),
)
def tools_sorted(probe: Probe) -> RuleResult:
    result = probe.tools_list().result()
    if result is None:
        return RuleResult.not_applicable("tools/list did not return a result")

    tools = result.get("tools")
    if not isinstance(tools, list) or len(tools) < 2:
        return RuleResult.not_applicable("fewer than two tools to order")

    names = [t.get("name", "") for t in tools if isinstance(t, dict)]
    ordered = sorted(names, key=lambda n: str(n).encode())
    if names != ordered:
        return RuleResult.failed(
            f"tools are not in byte-wise name order: {names} (byte-wise would be {ordered})",
            evidence=f"served {names}, byte-wise {ordered}",
        )
    return RuleResult.passed(f"{len(names)} tools are in byte-wise name order")


@rule(
    id="MCP/2026-07-28/SHOULD/tools-have-descriptions",
    title="Every tool has a description",
    severity=Severity.SHOULD,
    citation=f"{SPEC_BASE}/basic/index#tools",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Describe every tool. The description is what a model reads to choose between "
        "tools, so an undescribed tool is either never selected or selected by accident."
    ),
)
def tools_described(probe: Probe) -> RuleResult:
    result = probe.tools_list().result()
    if result is None:
        return RuleResult.not_applicable("tools/list did not return a result")

    tools = result.get("tools")
    if not isinstance(tools, list) or not tools:
        return RuleResult.not_applicable("this server advertises no tools")

    undescribed = [
        t.get("name", "<unnamed>")
        for t in tools
        if not isinstance(t, dict) or not str(t.get("description", "")).strip()
    ]
    if undescribed:
        return RuleResult.failed(f"{len(undescribed)} tools have no description: {undescribed}")
    return RuleResult.passed(f"all {len(tools)} tools are described")
