"""The migration plan, and the two claims its docstring makes about itself.

`plan.py` says two things a reader has to be able to check:

1. The ranking is declared rather than editorial -- a total sort over stored
   fields. `test_the_order_is_total_and_stable` holds it to that.
2. A change nobody can settle from the wire is reported as unknown, never as
   clear. `test_an_undetectable_change_is_never_reported_clear` holds it to
   that, and it is the more important of the two: a migration report that calls
   three unverifiable changes "done" is an INDETERMINATE scored as a PASS,
   which is the failure mode the whole rule engine exists to prevent.
"""

from __future__ import annotations

import pytest

from sentinel.catalog.base import REGISTRY, Outcome, RuleResult
from sentinel.catalog.deprecations import Confidence
from sentinel.grade import Finding, ScanReport
from sentinel.plan import (
    BREAKING_CHANGES,
    Impact,
    build_plan,
    render_json,
    render_text,
)

pytestmark = pytest.mark.unit

ALL_RULES = {r.id: r for r in REGISTRY.all(include_deprecated=True)}


def _report(outcomes: dict[str, Outcome]) -> ScanReport:
    findings = []
    for rule_id, outcome in outcomes.items():
        result = {
            Outcome.PASS: RuleResult.passed("seeded"),
            Outcome.FAIL: RuleResult.failed("seeded"),
            Outcome.INDETERMINATE: RuleResult.indeterminate("seeded"),
            Outcome.NOT_APPLICABLE: RuleResult.not_applicable("seeded"),
        }[outcome]
        findings.append(Finding(rule=ALL_RULES[rule_id], result=result, elapsed_s=0.0))
    return ScanReport(
        endpoint="http://example.invalid/mcp",
        spec_revision="2026-07-28",
        findings=findings,
    )


# ------------------------------------------------------------ the registry itself


def test_every_change_names_rules_that_exist() -> None:
    """A change naming a rule that does not exist reports itself clear forever.

    Silently, and in the safe-looking direction. This is the assertion that
    catches a rule id being renamed out from under this table.
    """
    unknown = {
        (c.id, rule_id)
        for c in BREAKING_CHANGES
        for rule_id in c.detected_by
        if rule_id not in ALL_RULES
    }
    assert not unknown, f"breaking changes name rules that do not exist: {unknown}"


def test_every_change_carries_remediation_worth_reading() -> None:
    for c in BREAKING_CHANGES:
        assert len(c.remediation) >= 40, f"{c.id} remediation is too thin"
        assert c.remediation[0].isupper(), f"{c.id} remediation should read as a sentence"
        assert c.effort_hours > 0, f"{c.id} has no effort estimate"


def test_change_ids_are_unique() -> None:
    ids = [c.id for c in BREAKING_CHANGES]
    assert len(ids) == len(set(ids))


def test_some_changes_are_genuinely_undetectable() -> None:
    """The failing direction for the registry.

    If every change grew a detection, the UNKNOWN branch below would stop being
    exercised and the honesty this module claims would be untested.
    """
    undetectable = [c.id for c in BREAKING_CHANGES if not c.detected_by]
    assert undetectable, "no undetectable changes; the unknown path is now dead code"


# ------------------------------------------------------------------- the ranking


def test_the_order_is_total_and_stable() -> None:
    """The claim the module docstring makes. Two runs, one order, no ties."""
    report = _report({})
    first = [f.change.id for f in build_plan(report).findings]
    second = [f.change.id for f in build_plan(report).findings]
    assert first == second, "the order is not stable across runs"

    keys = [f.sort_key for f in build_plan(report).findings]
    assert len(set(keys)) == len(keys), "two changes sort identically; the order is not total"
    assert keys == sorted(keys), "findings are not in sort_key order"


def test_blocking_changes_outrank_degrading_ones() -> None:
    plan = build_plan(_report({}))
    impacts = [f.change.impact for f in plan.findings]
    first_degrading = impacts.index(Impact.DEGRADING)
    assert Impact.BLOCKING not in impacts[first_degrading:], (
        "a blocking change sorted below a degrading one"
    )


# ----------------------------------------------------------------- the reporting


def test_a_failing_rule_makes_its_change_outstanding() -> None:
    plan = build_plan(_report({"MCP/2026-07-28/MUST/discover-implemented": Outcome.FAIL}))
    discover = next(f for f in plan.findings if f.change.id == "discover-required")
    assert discover.outstanding
    assert discover.confidence is Confidence.OBSERVED
    assert plan.outstanding_hours >= discover.change.effort_hours


def test_a_passing_rule_makes_its_change_clear() -> None:
    plan = build_plan(_report({"MCP/2026-07-28/MUST/discover-implemented": Outcome.PASS}))
    discover = next(f for f in plan.findings if f.change.id == "discover-required")
    assert not discover.outstanding
    assert discover.confidence is Confidence.OBSERVED
    assert discover in plan.clear


def test_an_undetectable_change_is_never_reported_clear() -> None:
    """The invariant that matters.

    A change with no black-box detection must land in `undetectable`, never in
    `clear`, no matter what else the scan saw.
    """
    plan = build_plan(_report({}))
    for f in plan.findings:
        if not f.change.detected_by:
            assert f.confidence is Confidence.UNKNOWN
            assert f in plan.undetectable
            assert f not in plan.clear


def test_an_indeterminate_rule_does_not_count_as_done() -> None:
    """A rule the harness could not settle leaves its change unknown."""
    plan = build_plan(
        _report({"MCP/2026-07-28/MUST/sampling-create-message-removed": Outcome.INDETERMINATE})
    )
    mrtr = next(f for f in plan.findings if f.change.id == "mrtr-replaces-server-initiated")
    assert mrtr.confidence is Confidence.UNKNOWN
    assert mrtr not in plan.clear


def test_effort_excludes_the_undetectable() -> None:
    """Summing unknown work would make a guess look like an estimate."""
    plan = build_plan(_report({}))
    assert plan.outstanding_hours == 0, "nothing failed, so nothing is outstanding"
    assert plan.undetectable, "the undetectable set should not be empty"


def test_the_text_report_says_it_is_not_a_verdict() -> None:
    rendered = render_text(build_plan(_report({})))
    assert "never fails a gate" in rendered
    assert "NOT CHECKABLE FROM HERE" in rendered


def test_the_json_report_carries_confidence_per_change() -> None:
    payload = render_json(build_plan(_report({})))
    assert payload["breaking_changes"] == len(BREAKING_CHANGES)
    changes = payload["changes"]
    assert isinstance(changes, list)
    for entry in changes:
        assert entry["confidence"] in {c.value for c in Confidence}
        assert "effort_hours" in entry
