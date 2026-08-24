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
    Registry,
    RuleResult,
    Severity,
    Verifiability,
    validate_registry,
)

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
