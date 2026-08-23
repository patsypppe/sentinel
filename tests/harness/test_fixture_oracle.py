"""The harness graded against its own fixtures.

`docs/HANDOFF.md` §9.5:

    "Together they are the harness's own oracle: RECALL is the fraction of
    seeded violations detected against the non-conformant fixture;
    FALSE-POSITIVE RATE is the count of failures reported against the conformant
    one, which must be zero. … A scanner that cannot state its own recall is
    asking to be trusted rather than earning it."

The denominator comes from `SEEDED_VIOLATIONS` in the fixture itself, not from
anything in the harness. A scanner that supplied its own denominator would be
grading its own homework.
"""

from __future__ import annotations

import pytest

from sentinel.catalog.base import Outcome, Severity
from sentinel.grade import EXIT_GATE_FAILED, EXIT_OK, run_scan
from server.nonconformant import SEEDED_VIOLATIONS

pytestmark = pytest.mark.unit


def test_nonconformant_fixture_trips_at_least_twenty_musts(nonconformant_endpoint: str) -> None:
    """§9 definition of done: "the non-conformant fixture trips at least twenty"."""
    report = run_scan(nonconformant_endpoint)
    failures = report.must_failures
    assert len(failures) >= 20, (
        f"only {len(failures)} MUST rules failed against a fixture with "
        f"{len(SEEDED_VIOLATIONS)} seeded violations:\n"
        + "\n".join(f"  {f.rule.id}" for f in failures)
    )


def test_recall_against_seeded_violations(nonconformant_endpoint: str) -> None:
    """Every violation the fixture admits to must be detected.

    The fixture tags each one in a comment AND lists it, so a violation that
    exists in the code but not in the list is caught by
    test_seeded_list_matches_the_tagged_code below. Between the two, recall is
    measured against what the fixture actually does.
    """
    report = run_scan(nonconformant_endpoint)
    detected = {f.rule.id for f in report.must_failures}
    seeded = set(SEEDED_VIOLATIONS)

    missed = seeded - detected
    recall = (len(seeded) - len(missed)) / len(seeded)

    assert not missed, (
        f"recall {recall:.0%} — {len(missed)} seeded violation(s) went undetected:\n"
        + "\n".join(f"  {rule_id}" for rule_id in sorted(missed))
    )


def test_conformant_fixture_trips_zero(conformant_endpoint: str) -> None:
    """The false-positive half. It must be zero.

    A rule that fails here is demanding something the specification does not,
    and would make every scan of a correct server report a defect.
    """
    report = run_scan(conformant_endpoint)
    failures = report.by_outcome(Outcome.FAIL)

    assert not failures, (
        f"{len(failures)} false positive(s) against a conformant server:\n"
        + "\n".join(f"  {f.rule.id}: {f.result.detail}" for f in failures)
    )


def test_conformant_fixture_passes_the_must_gate(conformant_endpoint: str) -> None:
    report = run_scan(conformant_endpoint)
    assert report.gate(Severity.MUST) == EXIT_OK


def test_nonconformant_fixture_fails_the_must_gate(nonconformant_endpoint: str) -> None:
    """A gate that can only pass proves nothing (§12)."""
    report = run_scan(nonconformant_endpoint)
    assert report.gate(Severity.MUST) == EXIT_GATE_FAILED


def test_indeterminate_never_fails_the_gate(conformant_endpoint: str) -> None:
    """§8.8: "INDETERMINATE never fails a gate but is always printed"."""
    report = run_scan(conformant_endpoint)
    assert report.indeterminate, "no rule reported INDETERMINATE, which is implausible"
    assert report.gate(Severity.MUST) == EXIT_OK, (
        "a scan with no failures and some indeterminate results failed the gate; "
        "an unsettleable rule must not be a verdict in either direction"
    )


def test_seeded_list_matches_the_tagged_code() -> None:
    """The fixture's declared violations and its tagged ones must agree.

    Without this, `SEEDED_VIOLATIONS` could drift from the code and the recall
    denominator would quietly stop describing the fixture — making recall look
    perfect by shrinking what it is measured against.
    """
    import pathlib
    import re

    source = (
        pathlib.Path(__file__).resolve().parents[2]
        / "fixtures" / "server" / "nonconformant.py"
    ).read_text()

    tagged = set(re.findall(r"VIOLATES (MCP/\S+)", source))
    listed = set(SEEDED_VIOLATIONS)

    assert listed == tagged, (
        "the seeded-violation list and the tagged code disagree:\n"
        f"  listed but not tagged: {sorted(listed - tagged)}\n"
        f"  tagged but not listed: {sorted(tagged - listed)}"
    )


def test_every_seeded_violation_names_a_real_rule() -> None:
    """A seeded violation naming a rule that does not exist would inflate the
    denominator with something no scanner could ever detect."""
    from sentinel.catalog.base import REGISTRY

    known = {r.id for r in REGISTRY}
    unknown = set(SEEDED_VIOLATIONS) - known
    assert not unknown, (
        f"the fixture seeds violations of rules that do not exist: {sorted(unknown)}"
    )


def test_scan_is_fast_enough_to_run_in_ci(conformant_endpoint: str) -> None:
    """A scan nobody will wait for is a scan nobody runs."""
    report = run_scan(conformant_endpoint)
    assert report.elapsed_s < 30.0, f"the scan took {report.elapsed_s:.1f}s"


def test_a_rule_that_raises_becomes_indeterminate_not_a_failure(conformant_endpoint: str) -> None:
    """A defect in the harness must not be reported as a defect in the server.

    This is the difference between a tool that says "you are wrong" and one that
    says "I broke", and conflating them is how a scanner loses its reader.
    """
    from sentinel.catalog.base import BaseRule, Registry, Severity, Verifiability

    def explode(_probe: object) -> object:
        raise RuntimeError("the rule itself is broken")

    registry = Registry()
    registry.register(
        BaseRule(
            id="MCP/2026-07-28/MUST/exploding",
            title="a rule with a bug in it",
            severity=Severity.MUST,
            citation="https://modelcontextprotocol.io/specification/2026-07-28/x",
            verifiability=Verifiability.BLACK_BOX,
            remediation="This rule has a defect and its result should be ignored entirely.",
            check=explode,  # type: ignore[arg-type]
        )
    )

    report = run_scan(conformant_endpoint, registry=registry)
    assert report.findings[0].outcome is Outcome.INDETERMINATE
    assert "defect in the harness" in report.findings[0].result.detail
    assert report.gate(Severity.MUST) == EXIT_OK


def test_unreachable_target_is_indeterminate_not_a_failure() -> None:
    """An outage is not a conformance failure. Reporting one as the other means
    a scan that ran against a stopped server reports 25 defects."""
    report = run_scan("http://127.0.0.1:1/mcp", timeout=1.0)

    assert not report.by_outcome(Outcome.FAIL), (
        "an unreachable server produced conformance FAILURES; an outage would be "
        "reported as a defective server"
    )
    assert report.indeterminate, "an unreachable server produced no indeterminate results"
