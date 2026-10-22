"""Beyond-spec style checks."""

from __future__ import annotations

from sentinel.catalog import checks
from sentinel.catalog.base import RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe


@rule(
    id="SENTINEL/STYLE/tools-sorted-by-name",
    title="tools/list returns tools in byte-wise name order",
    severity=Severity.SHOULD,
    rationale=(
        "The specification asks for a deterministic order and says nothing about which "
        "order. A stable but unsorted manifest conforms fully. Byte-wise name order is "
        "worth having anyway: it means two deployments advertising the same tools produce "
        "the same manifest bytes, which is what makes a manifest hash comparable across "
        "environments -- and comparable hashes are what drift detection runs on."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation=("Sort tools by name byte-wise (not case-insensitively, not by locale collation)."),
    introduced_in="0.2.0",
)
def tools_sorted_by_name(probe: Probe) -> RuleResult:
    return checks.tools_sorted_by_name(probe)


@rule(
    id="SENTINEL/STYLE/tools-have-descriptions",
    title="Every tool has a description",
    severity=Severity.SHOULD,
    rationale=(
        "`description` is optional in the specification's Tool schema, so a tool without one "
        "conforms. It is what a model reads to choose between tools, though, so an "
        "undescribed tool is either never selected or selected by accident."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation="Describe every tool in a sentence a model could choose it by.",
    introduced_in="0.4.0",
)
def tools_have_descriptions(probe: Probe) -> RuleResult:
    from sentinel.catalog.should.ordering import tools_described

    return tools_described.check(probe)
