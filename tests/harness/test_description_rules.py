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


def test_parameter_documentation_is_judged_the_way_a_model_reads_it() -> None:
    from sentinel.catalog.beyond.style import parameter_documented as documented

    tool = {
        "description": (
            "Search the web.\n\nArgs:\n    query: What to look for.\n"
            "    max_results (int): How many.\nReads a file at path."
        )
    }
    assert documented(tool, "query", {"type": "string"}) == "prose"
    assert documented(tool, "max_results", {"type": "integer"}) == "prose"
    assert documented(tool, "x", {"type": "string", "description": "hi"}) == "schema"
    # A sentence that merely contains the word does not document the parameter.
    assert documented({"description": "Read a file at path."}, "limit", {"type": "integer"}) is None
    # Self-evident only for a plain string; a structured `path` is not.
    assert documented({"description": "x"}, "path", {"type": "string"}) == "obvious"
    assert documented({"description": "x"}, "path", {"type": "array"}) is None
    nested = {
        "type": "array",
        "items": {"type": "object", "properties": {"a": {"description": "A."}}},
    }
    assert documented({"description": "x"}, "edits", nested) == "schema"
    assert documented({"description": "x"}, "edits", {"type": "array", "items": {}}) is None


def test_observed_wire_behaviour_is_extracted_for_aggregation() -> None:
    from sentinel.population import _observed

    assert _observed("HTTP 400, code -32600", "") == "HTTP 400, code -32600"
    both = "rejected: error code was -32601, not -32602; HTTP status was 200, not 400"
    assert _observed(None, both) == "HTTP 200, code -32601"
    assert _observed(None, "tools/list was SERVED with no header") == "request was served"
    assert _observed(None, "something else entirely") == "other"
