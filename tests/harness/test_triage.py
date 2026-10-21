"""Waivers, baselines, and the gate: accepted is not hidden, expired is not forgotten."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from sentinel import baseline as baseline_mod
from sentinel.catalog.base import Outcome, Severity
from sentinel.config import load_policy
from sentinel.fingerprint import fingerprint, target_identity
from sentinel.grade import EXIT_GATE_FAILED, EXIT_OK, Gate, ScanReport
from sentinel.runner import ScanOptions, scan_target
from sentinel.waivers import ConfigError, Waiver

pytestmark = pytest.mark.unit

TODAY = datetime.date(2026, 10, 1)


def scan(endpoint: str, tmp_path: Path, toml: str = "", **kw: object) -> ScanReport:
    cfg = tmp_path / "sentinel.toml"
    cfg.write_text(toml)
    policy = load_policy(config=cfg, env={})
    return scan_target(ScanOptions(endpoint=endpoint, policy=policy, today=TODAY, **kw))  # type: ignore[arg-type]


def a_must_failure(report: ScanReport) -> str:
    return next(
        f.rule.id
        for f in report.by_outcome(Outcome.FAIL)
        if f.rule.id.startswith("MCP/") and "/MUST/" in f.rule.id
    )


def test_identity_ignores_credentials_query_default_port_and_case() -> None:
    a = target_identity("HTTPS://User:pw@Example.com:443/mcp/?token=abc")
    assert a == "https://example.com/mcp"
    assert target_identity("https://example.com/mcp") == a
    assert target_identity("https://example.com:8443/mcp") != a
    assert target_identity("https://x/y", "broker-prod") == "name:broker-prod"


def test_a_fingerprint_depends_on_rule_target_and_key_and_nothing_else() -> None:
    base = fingerprint("r", "t", "k")
    assert base == fingerprint("r", "t", "k")
    assert (
        len(
            {
                base,
                fingerprint("r2", "t", "k"),
                fingerprint("r", "t2", "k"),
                fingerprint("r", "t", "k2"),
            }
        )
        == 4
    )


def test_fingerprints_are_stable_across_two_scans(
    nonconformant_endpoint: str, tmp_path: Path
) -> None:
    first = scan(nonconformant_endpoint, tmp_path)
    second = scan(nonconformant_endpoint, tmp_path)
    assert {f.fingerprint for f in first.by_outcome(Outcome.FAIL)} == {
        f.fingerprint for f in second.by_outcome(Outcome.FAIL)
    }


def test_findings_come_back_in_rule_order_whatever_finished_first(
    nonconformant_endpoint: str, tmp_path: Path
) -> None:
    report = scan(nonconformant_endpoint, tmp_path)
    ids = [f.rule.id for f in report.findings]
    assert ids == sorted(ids)


def test_an_active_waiver_stops_gating_but_keeps_the_finding(
    nonconformant_endpoint: str, tmp_path: Path
) -> None:
    rule = a_must_failure(scan(nonconformant_endpoint, tmp_path))
    waiver = (
        f'[[waivers]]\nrule = "{rule}"\nreason = "accepted for the migration window"\n'
        "expires_at = 2026-12-31\n"
    )
    report = scan(nonconformant_endpoint, tmp_path, waiver)
    finding = next(f for f in report.findings if f.rule.id == rule)
    assert finding.outcome is Outcome.FAIL
    assert finding.waived_by is not None
    assert finding.suppressed
    # Every other MUST failure still gates, so the build is still red.
    assert report.gate(Gate.spec(finding.rule.severity)) == EXIT_GATE_FAILED


def test_an_expired_waiver_refails_loudly(nonconformant_endpoint: str, tmp_path: Path) -> None:
    rule = a_must_failure(scan(nonconformant_endpoint, tmp_path))
    waiver = (
        f'[[waivers]]\nrule = "{rule}"\nreason = "accepted for the migration window"\n'
        "expires_at = 2026-09-30\n"
    )
    report = scan(nonconformant_endpoint, tmp_path, waiver)
    finding = next(f for f in report.findings if f.rule.id == rule)
    assert finding.waived_by is None
    assert finding.waiver_expired is not None
    assert not finding.suppressed
    assert any("EXPIRED" in note for note in report.waiver_notes)


def test_a_waiver_for_a_passing_rule_is_reported_as_unused(
    conformant_endpoint: str, tmp_path: Path
) -> None:
    rule = "MCP/2026-07-28/MUST/discover-implemented"
    waiver = (
        f'[[waivers]]\nrule = "{rule}"\nreason = "left over from an old incident"\n'
        "expires_at = 2026-12-31\n"
    )
    report = scan(conformant_endpoint, tmp_path, waiver)
    assert any("unused waiver" in note for note in report.waiver_notes)


def test_a_waiver_scoped_to_another_endpoint_does_not_apply(
    nonconformant_endpoint: str, tmp_path: Path
) -> None:
    rule = a_must_failure(scan(nonconformant_endpoint, tmp_path))
    waiver = (
        f'[[waivers]]\nrule = "{rule}"\nendpoint = "https://elsewhere.example/mcp"\n'
        'reason = "applies to a different server"\nexpires_at = 2026-12-31\n'
    )
    report = scan(nonconformant_endpoint, tmp_path, waiver)
    assert next(f for f in report.findings if f.rule.id == rule).waived_by is None


def test_waiver_matching_and_expiry_windows() -> None:
    w = Waiver(rule="r", reason="because reasons", expires_at=datetime.date(2026, 10, 10))
    assert w.matches("r", "https://a/mcp", None)
    assert not w.matches("other", "https://a/mcp", None)
    assert not w.expired(datetime.date(2026, 10, 10))
    assert w.expired(datetime.date(2026, 10, 11))
    assert w.expiring_soon(datetime.date(2026, 10, 1))
    assert not w.expiring_soon(datetime.date(2026, 9, 1))


def test_a_baseline_makes_the_gate_fire_only_on_what_is_new(
    nonconformant_endpoint: str, tmp_path: Path
) -> None:
    first = scan(nonconformant_endpoint, tmp_path)
    taken = baseline_mod.create(first)
    assert taken.entries
    assert first.gate(Gate.spec(Severity.MUST)) == EXIT_GATE_FAILED

    again = scan(nonconformant_endpoint, tmp_path, baseline=taken)
    assert all(f.baselined for f in again.by_outcome(Outcome.FAIL))
    assert again.gate(Gate.spec(Severity.MUST)) == EXIT_OK

    # An empty baseline accepts nothing, so the same server still gates.
    empty = baseline_mod.create(scan(nonconformant_endpoint, tmp_path))
    empty.entries.clear()
    assert (
        scan(nonconformant_endpoint, tmp_path, baseline=empty).gate(Gate.spec(Severity.MUST))
        == EXIT_GATE_FAILED
    )


def test_a_baseline_never_hides_what_was_fixed(nonconformant_endpoint: str, tmp_path: Path) -> None:
    taken = baseline_mod.create(scan(nonconformant_endpoint, tmp_path))
    taken.entries["f" * 64] = {"ruleId": "MCP/2026-07-28/MUST/was-broken", "detail": "old"}
    report = scan(nonconformant_endpoint, tmp_path, baseline=taken)
    assert report.fixed == ["f" * 64]
    pruned, dropped = baseline_mod.prune(taken, report)
    assert dropped == ["f" * 64]
    assert "f" * 64 not in pruned.entries


def test_a_rule_newer_than_the_baseline_is_new_by_construction(
    nonconformant_endpoint: str, tmp_path: Path
) -> None:
    taken = baseline_mod.create(scan(nonconformant_endpoint, tmp_path))
    victim = next(iter(taken.entries))
    rule = taken.entries.pop(victim)["ruleId"]
    taken.rule_ids.remove(rule)
    report = scan(nonconformant_endpoint, tmp_path, baseline=taken)
    finding = next(f for f in report.findings if f.fingerprint == victim)
    assert not finding.baselined
    assert finding.rule_is_new


def test_baseline_round_trips_and_refuses_the_wrong_revision(
    nonconformant_endpoint: str, tmp_path: Path
) -> None:
    taken = baseline_mod.create(scan(nonconformant_endpoint, tmp_path))
    path = tmp_path / "b.json"
    baseline_mod.save(taken, path)
    assert baseline_mod.load(path).entries == taken.entries

    text = path.read_text().replace('"specRevision": "2026-07-28"', '"specRevision": "2025-11-25"')
    path.write_text(text)
    with pytest.raises(ConfigError, match="cannot carry across"):
        baseline_mod.load(path)
    path.write_text("not json")
    with pytest.raises(ConfigError, match="cannot be read"):
        baseline_mod.load(path)


def test_disabling_a_rule_removes_it_from_the_run_and_lists_it(
    nonconformant_endpoint: str, tmp_path: Path
) -> None:
    rule = "MCP/2026-07-28/MUST/malformed-json-is-parse-error"
    report = scan(nonconformant_endpoint, tmp_path, f'[rules]\ndisable = ["{rule}"]\n')
    assert rule not in {f.rule.id for f in report.findings}
    assert report.policy["disabledRules"] == [rule]
