"""The rule catalog's own invariants."""

from __future__ import annotations

import ast
import pathlib

import pytest

from sentinel.catalog.base import (
    REGISTRY,
    RULE_ID_PATTERN,
    Namespace,
    Outcome,
    Severity,
    Verifiability,
    validate_registry,
)

pytestmark = pytest.mark.unit

HARNESS_SRC = pathlib.Path(__file__).resolve().parents[2] / "harness" / "src"


def test_every_rule_has_citation_and_remediation() -> None:
    """§9 (WP-9 pitfalls) calls out "writing a rule without a citation"
    specifically: a conformance claim with nothing to check it against is an
    opinion."""
    problems = validate_registry()
    assert not problems, "\n".join(f"{p.rule_id}: {p.problem}" for p in problems)


def test_catalog_has_at_least_twenty_five_must_rules() -> None:
    """§9 definition of done."""
    must = REGISTRY.by_severity(Severity.MUST)
    assert len(must) >= 25, f"only {len(must)} MUST rules"


def test_rule_ids_are_well_formed_and_unique() -> None:
    ids = [r.id for r in REGISTRY]
    assert len(ids) == len(set(ids)), "a rule id is registered twice"
    for rule_id in ids:
        assert RULE_ID_PATTERN.match(rule_id), f"{rule_id} is malformed"


def test_rule_ids_carry_their_severity() -> None:
    """Rule IDs are permanent (§8.8), so a report can be read years later. The
    severity being in the id means an old report is still interpretable without
    the catalog that produced it."""
    for r in REGISTRY:
        if r.namespace is not Namespace.MCP:
            # A SENTINEL/ id is namespaced by category, not severity, because a
            # beyond-spec rule's severity is this project's opinion rather than
            # something the specification assigned it.
            continue
        assert f"/{r.severity.upper()}/" in r.id, f"{r.id} does not carry {r.severity}"


def test_remediation_says_what_to_change() -> None:
    """§8.8: remediation is "what to change, not what is wrong". A report that
    only restates the failure leaves the reader where they started."""
    for r in REGISTRY:
        assert len(r.remediation) >= 40, f"{r.id}: remediation is too terse"
        assert r.remediation[0].isupper(), f"{r.id}: remediation is not a sentence"


def test_unverifiable_rules_cannot_report_a_pass() -> None:
    """The property §8.8 says a dishonest harness quietly breaks.

    `BaseRule.evaluate` coerces a non-INDETERMINATE result from an UNVERIFIABLE
    rule, so this holds even if a future edit makes one of them return PASS.
    """
    from sentinel.catalog.base import BaseRule, RuleResult

    lying = BaseRule(
        id="MCP/2026-07-28/MUST/pretend",
        title="a rule that tries to pass",
        severity=Severity.MUST,
        citation="https://modelcontextprotocol.io/specification/2026-07-28/x",
        verifiability=Verifiability.UNVERIFIABLE,
        remediation="x" * 50,
        check=lambda _: RuleResult.passed("everything is fine, trust me"),
    )
    assert lying.evaluate(None).outcome is Outcome.INDETERMINATE  # type: ignore[arg-type]


def test_unverifiable_rules_explain_what_would_settle_them() -> None:
    """A limitation nobody can act on is a shrug. Each unverifiable rule says
    what evidence WOULD settle it."""
    from sentinel.grade import unverifiable_rules

    rules = unverifiable_rules()
    assert rules, "no rules are marked unverifiable, which is implausible"
    for r in rules:
        detail = r.check(None).detail  # type: ignore[arg-type]
        assert "To settle it:" in detail, f"{r.id} does not say what would settle it"


def test_harness_never_imports_broker() -> None:
    """§5: "The harness must run against a URL. It may never import from
    broker/."

    Walked over the AST rather than grepped, so a mention of the broker in a
    comment or a docstring — of which there are many — is not a false positive.
    """
    offenders: list[str] = []

    for path in HARNESS_SRC.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                root = name.split(".")[0]
                if root in ("broker", "sentinel_broker"):
                    offenders.append(f"{path.name}: imports {name}")

    assert not offenders, "\n".join(offenders)


def test_probe_does_not_use_an_mcp_sdk() -> None:
    """§9.4: "an SDK that helpfully adds Mcp-Method makes the rule requiring
    Mcp-Method untestable"."""
    banned = {"mcp", "modelcontextprotocol", "fastmcp", "mcp_sdk"}
    offenders: list[str] = []

    for path in (HARNESS_SRC / "sentinel" / "probe").rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if name.split(".")[0] in banned:
                    offenders.append(f"{path.name}: imports {name}")

    assert not offenders, "\n".join(offenders)


def test_connection_independence_rule_exists_and_passes_the_conformant_fixture(
    conformant_endpoint: str,
) -> None:
    """The MUST the deprecated deterministic-ordering rule stood in for.

    "MUST NOT vary per-connection" needs two connections to observe; twenty
    calls on one connection cannot see it.
    """
    from sentinel.probe.client import Probe

    by_id = {r.id: r for r in REGISTRY.all()}
    rule = by_id["MCP/2026-07-28/MUST/tools-list-connection-independent"]

    with Probe(conformant_endpoint) as probe:
        result = rule.evaluate(probe)

    assert result.outcome is Outcome.PASS, result.detail


def test_legacy_range_rule_fires_on_the_nonconformant_fixture(
    nonconformant_endpoint: str,
) -> None:
    from sentinel.probe.client import Probe

    rule = {r.id: r for r in REGISTRY.all()}["MCP/2026-07-28/SHOULD/no-errors-in-legacy-range"]
    with Probe(nonconformant_endpoint) as probe:
        assert rule.evaluate(probe).outcome is Outcome.FAIL


def test_legacy_range_rule_passes_the_conformant_fixture(conformant_endpoint: str) -> None:
    from sentinel.probe.client import Probe

    rule = {r.id: r for r in REGISTRY.all()}["MCP/2026-07-28/SHOULD/no-errors-in-legacy-range"]
    with Probe(conformant_endpoint) as probe:
        assert rule.evaluate(probe).outcome in (Outcome.PASS, Outcome.NOT_APPLICABLE)


#: The two per-request `_meta` fields the specification grades Required: Yes.
#: `missing-capability-error-shape` is not here: neither fixture returns -32021,
#: so it is NOT_APPLICABLE against both and a parametrised PASS/FAIL pair over it
#: would be asserting something no fixture exercises.
META_RULES = [
    "MCP/2026-07-28/MUST/missing-client-capabilities-rejected",
    "MCP/2026-07-28/MUST/missing-protocol-version-rejected",
]


@pytest.mark.parametrize("rule_id", META_RULES)
def test_meta_rules_pass_the_conformant_fixture(rule_id: str, conformant_endpoint: str) -> None:
    from sentinel.probe.client import Probe

    rule = {r.id: r for r in REGISTRY.all()}[rule_id]
    with Probe(conformant_endpoint) as probe:
        result = rule.evaluate(probe)
    assert result.outcome is Outcome.PASS, f"{rule_id}: {result.detail}"


@pytest.mark.parametrize("rule_id", META_RULES)
def test_meta_rules_fail_the_nonconformant_fixture(
    rule_id: str, nonconformant_endpoint: str
) -> None:
    from sentinel.probe.client import Probe

    rule = {r.id: r for r in REGISTRY.all()}[rule_id]
    with Probe(nonconformant_endpoint) as probe:
        result = rule.evaluate(probe)
    assert result.outcome is Outcome.FAIL, f"{rule_id}: {result.detail}"


#: The HTTP layer: status codes, required headers, Origin, Content-Type.
#:
#: `notification-not-answered-with-a-result` is not here, and neither is the
#: SHOULD. The notification rule PASSes on 202 *or* on any HTTP error status —
#: the specification permits refusing, because this revision defines no
#: client-to-server notifications over Streamable HTTP — so it has two passing
#: shapes and belongs in its own assertion rather than in a table that says
#: "PASS". `get-delete-405` is a SHOULD and is asserted separately for the same
#: reason the severity exists: it is not part of the MUST gate.
HTTP_RULES = [
    "MCP/2026-07-28/MUST/unknown-method-http-404",
    "MCP/2026-07-28/MUST/protocol-version-header-required",
    "MCP/2026-07-28/MUST/protocol-version-header-body-mismatch-rejected",
    "MCP/2026-07-28/MUST/invalid-origin-rejected",
    "MCP/2026-07-28/MUST/response-content-type-valid",
]


@pytest.mark.parametrize("rule_id", HTTP_RULES)
def test_http_rules_pass_the_conformant_fixture(rule_id: str, conformant_endpoint: str) -> None:
    from sentinel.probe.client import Probe

    rule = {r.id: r for r in REGISTRY.all()}[rule_id]
    with Probe(conformant_endpoint) as probe:
        result = rule.evaluate(probe)
    assert result.outcome is Outcome.PASS, f"{rule_id}: {result.detail}"


@pytest.mark.parametrize("rule_id", HTTP_RULES)
def test_http_rules_fail_the_nonconformant_fixture(
    rule_id: str, nonconformant_endpoint: str
) -> None:
    from sentinel.probe.client import Probe

    rule = {r.id: r for r in REGISTRY.all()}[rule_id]
    with Probe(nonconformant_endpoint) as probe:
        result = rule.evaluate(probe)
    assert result.outcome is Outcome.FAIL, f"{rule_id}: {result.detail}"


NOTIFICATION_RULE = "MCP/2026-07-28/MUST/notification-not-answered-with-a-result"


def test_notification_rule_passes_the_conformant_fixture(conformant_endpoint: str) -> None:
    """The conformant fixture answers 202 with an empty body.

    Refusing with an HTTP error would satisfy the rule too, so the assertion
    names the branch the fixture actually exercises — otherwise the harder half
    of the requirement, "202 Accepted with no body", would never be tested.
    """
    from sentinel.probe.client import Probe

    rule = {r.id: r for r in REGISTRY.all()}[NOTIFICATION_RULE]
    with Probe(conformant_endpoint) as probe:
        result = rule.evaluate(probe)
    assert result.outcome is Outcome.PASS, result.detail
    assert "202" in result.detail


def test_notification_rule_fails_the_nonconformant_fixture(nonconformant_endpoint: str) -> None:
    from sentinel.probe.client import Probe

    rule = {r.id: r for r in REGISTRY.all()}[NOTIFICATION_RULE]
    with Probe(nonconformant_endpoint) as probe:
        result = rule.evaluate(probe)
    assert result.outcome is Outcome.FAIL, result.detail


GET_DELETE_RULE = "MCP/2026-07-28/SHOULD/get-delete-405"


def test_get_delete_rule_passes_the_conformant_fixture(conformant_endpoint: str) -> None:
    from sentinel.probe.client import Probe

    rule = {r.id: r for r in REGISTRY.all()}[GET_DELETE_RULE]
    with Probe(conformant_endpoint) as probe:
        result = rule.evaluate(probe)
    assert result.outcome is Outcome.PASS, result.detail


def test_get_delete_rule_fails_the_nonconformant_fixture(nonconformant_endpoint: str) -> None:
    from sentinel.probe.client import Probe

    rule = {r.id: r for r in REGISTRY.all()}[GET_DELETE_RULE]
    with Probe(nonconformant_endpoint) as probe:
        result = rule.evaluate(probe)
    assert result.outcome is Outcome.FAIL, result.detail
