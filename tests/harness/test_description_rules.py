"""The tool-description lint rules must separate the practice servers, and `demo` must run."""

from __future__ import annotations

import subprocess
import sys

import pytest

from sentinel.catalog.base import REGISTRY, Outcome
from sentinel.probe.client import Probe

pytestmark = pytest.mark.unit

RULES = [
    "SENTINEL/STYLE/description-states-purpose",
    "SENTINEL/STYLE/parameters-are-described",
]


def _outcome(rule_id: str, endpoint: str) -> Outcome:
    rule = {r.id: r for r in REGISTRY.all()}[rule_id]
    with Probe(endpoint) as probe:
        return rule.evaluate(probe).outcome


@pytest.mark.parametrize("rule_id", RULES)
def test_the_broken_server_fails_and_the_correct_one_passes(
    rule_id: str, nonconformant_endpoint: str, conformant_endpoint: str
) -> None:
    assert _outcome(rule_id, nonconformant_endpoint) is Outcome.FAIL
    assert _outcome(rule_id, conformant_endpoint) is Outcome.PASS


def test_demo_runs_end_to_end_and_shows_both_verdicts() -> None:
    done = subprocess.run(
        [sys.executable, "-m", "sentinel.cli", "demo"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert "verdict: FAIL (exit code 1)" in done.stdout
    assert "verdict: PASS (exit code 0)" in done.stdout


def test_a_legacy_only_server_is_called_out_at_the_top_of_the_report() -> None:
    from sentinel.grade import ScanReport
    from sentinel.report import text

    report = ScanReport(endpoint="http://x/mcp", spec_revision="2026-07-28")
    report.generation, report.generation_detail = "legacy", "negotiated '2025-11-25'"
    assert "PREVIOUS MCP revision" in text.render(report, color=False)
