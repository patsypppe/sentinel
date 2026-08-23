"""SARIF output shape.

The point of SARIF is that GitHub code scanning renders it natively. That only
helps if the document is well-formed and if the mappings are honest — an
INDETERMINATE rendered as a pass would look like a clean scan in the one place
most people would see it.
"""

from __future__ import annotations

import json

import pytest

from sentinel.grade import run_scan
from sentinel.report.sarif import SARIF_VERSION, render

pytestmark = pytest.mark.unit


def test_sarif_has_the_required_top_level_shape(conformant_endpoint: str) -> None:
    doc = render(run_scan(conformant_endpoint))

    assert doc["version"] == SARIF_VERSION
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(doc["runs"]) == 1

    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "sentinel"
    assert driver["rules"], "no rules were declared"
    assert doc["runs"][0]["results"], "no results were emitted"


def test_every_result_references_a_declared_rule(conformant_endpoint: str) -> None:
    """A result whose ruleId is not in the driver's rule list renders without its
    help text, which is where the remediation lives."""
    doc = render(run_scan(conformant_endpoint))
    run = doc["runs"][0]

    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    referenced = {r["ruleId"] for r in run["results"]}
    assert referenced <= declared, f"undeclared rules referenced: {referenced - declared}"


def test_every_rule_carries_its_citation_as_a_help_uri(conformant_endpoint: str) -> None:
    doc = render(run_scan(conformant_endpoint))
    for r in doc["runs"][0]["tool"]["driver"]["rules"]:
        assert r["helpUri"].startswith("https://modelcontextprotocol.io/"), r["id"]
        assert r["fullDescription"]["text"], r["id"]


def test_indeterminate_is_never_rendered_as_a_pass(conformant_endpoint: str) -> None:
    """The mapping that matters.

    SARIF has no "could not determine" level, and the tempting shortcut is to
    emit these as passes. GitHub's UI is where most people would see the result,
    so a false pass there is the most consequential place to put one.
    """
    report = run_scan(conformant_endpoint)
    indeterminate_ids = {f.rule.id for f in report.indeterminate}
    assert indeterminate_ids, "this test is vacuous with no indeterminate rules"

    doc = render(report)
    for result in doc["runs"][0]["results"]:
        if result["ruleId"] in indeterminate_ids:
            assert result["kind"] != "pass", f"{result['ruleId']} was rendered as a pass"
            assert result["kind"] == "informational"
            assert result["message"]["text"].startswith("indeterminate"), (
                "the message must say so plainly; the kind alone is not visible in the UI"
            )


def test_must_failures_are_errors_and_should_failures_are_warnings(
    nonconformant_endpoint: str,
) -> None:
    report = run_scan(nonconformant_endpoint)
    doc = render(report)

    severity_by_id = {f.rule.id: f.rule.severity.value for f in report.findings}
    outcome_by_id = {f.rule.id: f.outcome.value for f in report.findings}

    for result in doc["runs"][0]["results"]:
        if outcome_by_id[result["ruleId"]] != "fail":
            continue
        want = "error" if severity_by_id[result["ruleId"]] == "must" else "warning"
        assert result["level"] == want, f"{result['ruleId']} is {result['level']}, want {want}"


def test_passing_results_carry_no_level(conformant_endpoint: str) -> None:
    """SARIF says `level` is meaningless for kind: pass, and some consumers
    reject a document that sets it."""
    doc = render(run_scan(conformant_endpoint))
    for result in doc["runs"][0]["results"]:
        if result["kind"] == "pass":
            assert "level" not in result, result["ruleId"]


def test_not_applicable_uses_sarifs_own_kind(nonconformant_endpoint: str) -> None:
    report = run_scan(nonconformant_endpoint)
    na = {f.rule.id for f in report.findings if f.outcome.value == "not_applicable"}
    if not na:
        pytest.skip("no rule reported not-applicable against this fixture")

    doc = render(report)
    for result in doc["runs"][0]["results"]:
        if result["ruleId"] in na:
            assert result["kind"] == "notApplicable"


def test_sarif_is_json_serialisable(conformant_endpoint: str) -> None:
    """It is written to a file and uploaded; a non-serialisable value would fail
    at the point where a human is least able to debug it."""
    doc = render(run_scan(conformant_endpoint))
    assert json.loads(json.dumps(doc)) == doc
