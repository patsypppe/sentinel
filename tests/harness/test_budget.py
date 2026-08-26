"""What a manifest costs, and the gate that can act on it.

Two things are under test here, and the second matters more than the first.

The pricing is arithmetic and is checked directly. The GATE SEPARATION is the
invariant: a `SENTINEL/OPS` rule must be able to fail `--gate ops` and must be
unable to fail `--gate must`. If the second half of that ever breaks, a budget
opinion this project holds starts masquerading as a conformance verdict about
the specification, which is the failure mode `ScanReport.gate` exists to
prevent. Both directions are asserted, because a separation only tested in the
direction that passes is not tested.
"""

from __future__ import annotations

import pytest

from sentinel.budget import BudgetPolicy, manifest_cost, schema_depth
from sentinel.catalog.base import (
    REGISTRY,
    Namespace,
    Outcome,
    RuleResult,
    Severity,
)
from sentinel.grade import (
    EXIT_GATE_FAILED,
    EXIT_OK,
    Finding,
    Gate,
    ScanReport,
)

pytestmark = pytest.mark.unit


def _tool(name: str, description: str = "", schema: dict | None = None) -> dict:
    return {
        "name": name,
        "description": description,
        "inputSchema": schema if schema is not None else {"type": "object"},
    }


def _report(*findings: Finding) -> ScanReport:
    return ScanReport(
        endpoint="http://example.invalid/mcp",
        spec_revision="2026-07-28",
        findings=list(findings),
    )


def _finding(rule_id: str, outcome: Outcome) -> Finding:
    rule = next(r for r in REGISTRY.all(include_deprecated=True) if r.id == rule_id)
    result = (
        RuleResult.failed("seeded for this test")
        if outcome is Outcome.FAIL
        else RuleResult.passed("seeded for this test")
    )
    return Finding(rule=rule, result=result, elapsed_s=0.0)


# --------------------------------------------------------------------- pricing


def test_the_manifest_costs_more_than_the_sum_of_its_tools() -> None:
    """The envelope is not free, and the report should not imply that it is."""
    total, per_tool = manifest_cost([_tool("a.one"), _tool("a.two")])
    assert len(per_tool) == 2
    assert total > sum(t.tokens for t in per_tool) - total  # sanity, not tautology
    assert total > 0


def test_key_order_does_not_change_the_count() -> None:
    """Two servers emitting the same manifest differently must price the same.

    This is what makes a budget comparable across deployments rather than a
    property of one server's JSON encoder.
    """
    a = {"name": "x", "description": "d", "inputSchema": {"type": "object"}}
    b = {"inputSchema": {"type": "object"}, "description": "d", "name": "x"}
    assert manifest_cost([a])[1][0].tokens == manifest_cost([b])[1][0].tokens


def test_a_non_dict_entry_is_skipped_rather_than_crashing() -> None:
    """A malformed manifest is the target's defect, not a reason to raise."""
    _, per_tool = manifest_cost([_tool("ok"), "not a tool", 42])
    assert [t.name for t in per_tool] == ["ok"]


@pytest.mark.parametrize(
    ("value", "expected", "why"),
    [
        ({}, 0, "an empty object has no depth"),
        ({"a": 1}, 1, "one level"),
        ({"a": {"b": 1}}, 2, "two levels"),
        ({"a": [{"b": 1}]}, 3, "arrays count as a level"),
        ({"a": {}}, 1, "an empty leaf object still occupied a level"),
    ],
)
def test_schema_depth(value: object, expected: int, why: str) -> None:
    assert schema_depth(value) == expected, why


def test_budget_policy_reports_whether_anything_was_asked_for() -> None:
    assert not BudgetPolicy().any_set
    assert BudgetPolicy(manifest_tokens=1).any_set


# ------------------------------------------------------------ gate separation

BUDGET_RULE = "SENTINEL/OPS/manifest-token-budget"
SPEC_RULE = "MCP/2026-07-28/MUST/discover-implemented"


def test_a_beyond_spec_failure_fails_a_beyond_spec_gate() -> None:
    report = _report(_finding(BUDGET_RULE, Outcome.FAIL))
    assert report.gate(Gate.beyond("ops")) == EXIT_GATE_FAILED


def test_a_beyond_spec_failure_cannot_fail_a_conformance_gate() -> None:
    """The invariant. A budget is an opinion; a MUST is the specification.

    Letting the first fail `--gate must` would make a conformance verdict
    unfalsifiable, because the target could not tell which claim it failed.
    """
    report = _report(_finding(BUDGET_RULE, Outcome.FAIL))
    assert report.gate(Gate.spec(Severity.MUST)) == EXIT_OK
    assert report.gate(Severity.MUST) == EXIT_OK, "the legacy bare-severity call too"


def test_a_spec_failure_cannot_fail_a_beyond_spec_gate() -> None:
    """The other direction: `--gate ops` makes an operational claim only."""
    report = _report(_finding(SPEC_RULE, Outcome.FAIL))
    assert report.gate(Gate.beyond("ops")) == EXIT_GATE_FAILED - 1  # EXIT_OK
    assert report.gate(Gate.spec(Severity.MUST)) == EXIT_GATE_FAILED


def test_one_category_does_not_gate_another() -> None:
    report = _report(_finding(BUDGET_RULE, Outcome.FAIL))
    assert report.gate(Gate.beyond("style")) == EXIT_OK
    assert report.gate(Gate.beyond("security")) == EXIT_OK


def test_a_bare_severity_still_means_exactly_what_it_meant() -> None:
    """Every existing caller and CI invocation keeps its behaviour."""
    report = _report(_finding(SPEC_RULE, Outcome.FAIL))
    assert report.gate(Severity.MUST) == report.gate(Gate.spec(Severity.MUST))
    assert report.gate(None) == EXIT_OK


def test_every_budget_rule_is_beyond_spec_and_carries_a_rationale() -> None:
    """A SENTINEL rule with a citation would be claiming the spec requires it."""
    budget_rules = [r for r in REGISTRY.all() if r.category == "OPS"]
    assert budget_rules, "no OPS rules registered; the gate below tests nothing"
    for r in budget_rules:
        assert r.namespace is Namespace.SENTINEL
        assert r.rationale and not r.citation
        assert len(r.remediation) >= 40


def test_gate_str_names_the_gate_a_user_typed() -> None:
    assert str(Gate.beyond("ops")) == "ops"
    assert str(Gate.spec(Severity.MUST)) == "must"
