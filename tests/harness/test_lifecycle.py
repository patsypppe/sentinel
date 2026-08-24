"""The rule lifecycle.

Rule IDs are permanent (HANDOFF §8.8). When a rule's severity turns out to be
wrong, the catalog deprecates it and publishes a successor rather than editing
the published ID -- otherwise every historical report becomes uninterpretable.
"""

from __future__ import annotations

import pytest

from sentinel.catalog.base import (
    BaseRule,
    Namespace,
    Outcome,
    Registry,
    RuleResult,
    Severity,
    Verifiability,
    validate_registry,
)
from sentinel.grade import EXIT_GATE_FAILED, EXIT_OK, Finding, ScanReport, run_scan
from sentinel.report.json_report import render as render_json
from sentinel.report.text import render as render_text

pytestmark = pytest.mark.unit


def _rule(
    rule_id: str,
    *,
    severity: Severity = Severity.MUST,
    deprecated_in: str | None = None,
    superseded_by: str | None = None,
    citation: str = "https://modelcontextprotocol.io/specification/2026-07-28/basic",
    rationale: str = "",
) -> BaseRule:
    return BaseRule(
        id=rule_id,
        title="a title",
        severity=severity,
        citation=citation,
        rationale=rationale,
        verifiability=Verifiability.BLACK_BOX,
        remediation="Change the thing that is wrong, in this specific way.",
        check=lambda probe: RuleResult.passed(),
        fixtures=["nonconformant", "conformant"],
        deprecated_in=deprecated_in,
        superseded_by=superseded_by,
    )


def test_namespace_is_derived_from_the_id() -> None:
    assert _rule("MCP/2026-07-28/MUST/a").namespace is Namespace.MCP
    beyond_spec = _rule("SENTINEL/STYLE/a", citation="", rationale="x" * 25)
    assert beyond_spec.namespace is Namespace.SENTINEL


def test_slug_is_the_last_segment() -> None:
    assert _rule("MCP/2026-07-28/MUST/tools-are-named").slug == "tools-are-named"


def test_all_excludes_deprecated_rules_by_default() -> None:
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/live"))
    reg.register(_rule("MCP/2026-07-28/MUST/gone", deprecated_in="0.2.0",
                       superseded_by="MCP/2026-07-28/MUST/live"))

    assert [r.id for r in reg.all()] == ["MCP/2026-07-28/MUST/live"]
    assert len(reg.all(include_deprecated=True)) == 2


def test_by_severity_honours_include_deprecated() -> None:
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/live"))
    reg.register(_rule("MCP/2026-07-28/MUST/gone", deprecated_in="0.2.0",
                       superseded_by="MCP/2026-07-28/MUST/live"))

    assert len(reg.by_severity(Severity.MUST)) == 1
    assert len(reg.by_severity(Severity.MUST, include_deprecated=True)) == 2


def test_deprecated_rule_must_name_a_successor_that_exists() -> None:
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/gone", deprecated_in="0.2.0",
                       superseded_by="MCP/2026-07-28/SHOULD/nowhere"))

    problems = validate_registry(reg)
    assert any("superseded_by" in p.problem for p in problems)


def test_deprecated_rule_without_a_successor_is_a_problem() -> None:
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/gone", deprecated_in="0.2.0"))

    problems = validate_registry(reg)
    assert any("successor" in p.problem or "superseded_by" in p.problem for p in problems)


def test_two_live_rules_may_not_share_a_slug() -> None:
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/same-slug"))
    reg.register(_rule("MCP/2026-07-28/SHOULD/same-slug", severity=Severity.SHOULD))

    problems = validate_registry(reg)
    assert any("slug" in p.problem for p in problems)


def test_a_deprecated_rule_and_its_successor_may_share_a_slug() -> None:
    """This is the whole point of the mechanism."""
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/same-slug", deprecated_in="0.2.0",
                       superseded_by="MCP/2026-07-28/SHOULD/same-slug"))
    reg.register(_rule("MCP/2026-07-28/SHOULD/same-slug", severity=Severity.SHOULD))

    assert validate_registry(reg) == []


def test_sentinel_namespace_requires_a_rationale_and_no_citation() -> None:
    reg = Registry()
    reg.register(_rule("SENTINEL/STYLE/a", citation="", rationale=""))
    problems = validate_registry(reg)
    assert any("rationale" in p.problem for p in problems)

    reg2 = Registry()
    reg2.register(
        _rule("SENTINEL/STYLE/a",
              citation="https://modelcontextprotocol.io/specification/2026-07-28/basic",
              rationale="x" * 25)
    )
    assert any("citation" in p.problem for p in validate_registry(reg2))


def test_mcp_namespace_rejects_a_rationale() -> None:
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/a", rationale="x" * 25))
    assert any("rationale" in p.problem for p in validate_registry(reg))


# --- Task 2: the lifecycle as it reaches a scan, a gate and a report ---------

SPEC_CITATION = "https://modelcontextprotocol.io/specification/2026-07-28/basic"


def _finding(
    rule_id: str,
    outcome: Outcome,
    severity: Severity,
    *,
    deprecated_in: str | None = None,
    superseded_by: str | None = None,
) -> Finding:
    beyond_spec = rule_id.startswith("SENTINEL/")
    return Finding(
        rule=_rule(
            rule_id,
            severity=severity,
            citation="" if beyond_spec else SPEC_CITATION,
            rationale="x" * 25 if beyond_spec else "",
            deprecated_in=deprecated_in,
            superseded_by=superseded_by,
        ),
        result=RuleResult(outcome, "detail"),
        elapsed_s=0.0,
    )


def _report(*findings: Finding) -> ScanReport:
    return ScanReport(
        endpoint="http://x/mcp",
        spec_revision="2026-07-28",
        findings=list(findings),
        started_at=0.0,
        elapsed_s=0.0,
    )


def test_gate_ignores_the_beyond_spec_namespace() -> None:
    """A style opinion must never be able to fail a conformance gate."""
    report = _report(
        _finding("MCP/2026-07-28/MUST/ok", Outcome.PASS, Severity.MUST),
        _finding("SENTINEL/STYLE/opinion", Outcome.FAIL, Severity.SHOULD),
    )
    assert report.gate(Severity.MUST) == EXIT_OK
    assert report.gate(Severity.SHOULD) == EXIT_OK


def test_gate_still_fails_on_a_must_in_the_mcp_namespace() -> None:
    report = _report(_finding("MCP/2026-07-28/MUST/bad", Outcome.FAIL, Severity.MUST))
    assert report.gate(Severity.MUST) == EXIT_GATE_FAILED


def test_a_beyond_spec_failure_is_still_reported() -> None:
    """Excluded from the gate is not the same as hidden."""
    report = _report(_finding("SENTINEL/STYLE/opinion", Outcome.FAIL, Severity.SHOULD))
    assert report.by_outcome(Outcome.FAIL) != []
    assert "SENTINEL/STYLE/opinion" in render_text(report, color=False)


def test_run_scan_excludes_deprecated_rules_unless_asked() -> None:
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/live"))
    reg.register(_rule("MCP/2026-07-28/MUST/gone", deprecated_in="0.2.0",
                       superseded_by="MCP/2026-07-28/MUST/live"))

    # Nothing here touches the network: every rule's check ignores the probe.
    endpoint = "http://127.0.0.1:1/mcp"
    default = run_scan(endpoint, registry=reg, timeout=1.0)
    assert [f.rule.id for f in default.findings] == ["MCP/2026-07-28/MUST/live"]

    everything = run_scan(endpoint, registry=reg, timeout=1.0, include_deprecated=True)
    assert len(everything.findings) == 2


def test_run_scan_still_honours_only_alongside_include_deprecated() -> None:
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/live"))
    reg.register(_rule("MCP/2026-07-28/MUST/gone", deprecated_in="0.2.0",
                       superseded_by="MCP/2026-07-28/MUST/live"))

    report = run_scan(
        "http://127.0.0.1:1/mcp",
        registry=reg,
        timeout=1.0,
        only={"MCP/2026-07-28/MUST/gone"},
        include_deprecated=True,
    )
    assert [f.rule.id for f in report.findings] == ["MCP/2026-07-28/MUST/gone"]


def test_the_text_report_marks_a_deprecated_finding_and_names_its_successor() -> None:
    report = _report(
        _finding(
            "MCP/2026-07-28/MUST/gone",
            Outcome.FAIL,
            Severity.MUST,
            deprecated_in="0.2.0",
            superseded_by="MCP/2026-07-28/SHOULD/live",
        )
    )
    rendered = render_text(report, color=False)
    assert "DEPRECATED MCP/2026-07-28/MUST/gone" in rendered
    assert "superseded by MCP/2026-07-28/SHOULD/live" in rendered


def test_a_live_finding_is_not_marked_deprecated() -> None:
    rendered = render_text(
        _report(_finding("MCP/2026-07-28/MUST/bad", Outcome.FAIL, Severity.MUST)),
        color=False,
    )
    assert "DEPRECATED" not in rendered
    assert "superseded by" not in rendered


def test_the_json_report_carries_the_lifecycle_on_every_finding() -> None:
    report = _report(
        _finding(
            "MCP/2026-07-28/MUST/gone",
            Outcome.FAIL,
            Severity.MUST,
            deprecated_in="0.2.0",
            superseded_by="MCP/2026-07-28/SHOULD/live",
        ),
        _finding("SENTINEL/STYLE/opinion", Outcome.PASS, Severity.SHOULD),
    )
    rendered = render_json(report)

    # Additive only: the v2 schema bump is WP-24.
    assert rendered["schemaVersion"] == 1

    deprecated, opinion = rendered["findings"]
    assert deprecated["namespace"] == "MCP"
    assert deprecated["deprecated"] is True
    assert deprecated["supersededBy"] == "MCP/2026-07-28/SHOULD/live"
    assert opinion["namespace"] == "SENTINEL"
    assert opinion["deprecated"] is False
    assert opinion["supersededBy"] is None
