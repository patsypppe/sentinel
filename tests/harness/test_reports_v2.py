"""markdown, junit, html, JSON v2 and SARIF fingerprints."""

from __future__ import annotations

import copy
import dataclasses
import datetime
import json
import re
from xml.etree import ElementTree as ET

import pytest

from sentinel import baseline as baseline_mod
from sentinel.catalog.base import Outcome, RuleResult
from sentinel.config import load_policy
from sentinel.grade import ScanReport
from sentinel.report import FORMATS, render_report
from sentinel.report import markdown as md
from sentinel.runner import ScanOptions, scan_target

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def failing(nonconformant_endpoint: str, tmp_path_factory: pytest.TempPathFactory) -> ScanReport:
    cfg = tmp_path_factory.mktemp("cfg") / "sentinel.toml"
    cfg.write_text("")
    return scan_target(
        ScanOptions(
            endpoint=nonconformant_endpoint,
            policy=load_policy(config=cfg, env={}),
            today=datetime.date(2026, 10, 1),
        )
    )


@pytest.fixture(scope="module")
def clean(conformant_endpoint: str, tmp_path_factory: pytest.TempPathFactory) -> ScanReport:
    cfg = tmp_path_factory.mktemp("cfg2") / "sentinel.toml"
    cfg.write_text("")
    return scan_target(
        ScanOptions(endpoint=conformant_endpoint, policy=load_policy(config=cfg, env={}))
    )


def test_every_format_renders_a_failing_and_a_clean_report(
    failing: ScanReport, clean: ScanReport
) -> None:
    for report in (failing, clean):
        for fmt in FORMATS:
            assert render_report(fmt, report).strip(), fmt


def test_an_unknown_format_is_refused() -> None:
    with pytest.raises(ValueError, match="not one of"):
        render_report("pdf", ScanReport(endpoint="x", spec_revision="r"))


def test_markdown_leads_with_the_verdict_and_unwraps_failures(
    failing: ScanReport, clean: ScanReport
) -> None:
    bad = md.render(failing)
    assert bad.splitlines()[0].endswith("**FAIL**")
    first_details = bad.index("<details")
    assert "#### ❌" in bad[:first_details], "failures must not hide inside <details>"
    assert md.render(clean).splitlines()[0].endswith("**PASS**")


def test_markdown_stays_under_githubs_comment_limit_and_says_what_it_dropped(
    failing: ScanReport,
) -> None:
    huge = copy.copy(failing)
    inflated = []
    for index in range(600):
        for finding in failing.findings:
            result = RuleResult.failed("x" * 400)
            inflated.append(dataclasses.replace(finding, result=result, fingerprint=f"{index}"))
    huge.findings = inflated
    rendered = md.render(huge)
    assert len(rendered) < 65_536
    assert "omitted to stay under GitHub's comment size limit" in rendered


def test_junit_never_renders_an_unsettled_rule_as_a_pass(failing: ScanReport) -> None:
    root = ET.fromstring(render_report("junit", failing))
    assert root.tag == "testsuite"
    cases = root.findall("testcase")
    assert len(cases) == len(failing.findings)
    by_id = {c.get("classname", "") + "/" + c.get("name", ""): c for c in cases}
    for finding in failing.findings:
        case = by_id[finding.rule.id]
        if finding.outcome is Outcome.FAIL and not finding.suppressed:
            assert case.find("failure") is not None
        elif finding.outcome is Outcome.INDETERMINATE:
            assert case.find("skipped") is not None
            assert case.find("failure") is None
    assert int(root.get("failures", "0")) == len(
        [f for f in failing.findings if f.outcome is Outcome.FAIL and not f.suppressed]
    )


def test_html_is_self_contained_and_escapes_what_a_server_says(failing: ScanReport) -> None:
    hostile = copy.copy(failing)
    first = failing.by_outcome(Outcome.FAIL)[0]
    hostile.findings = [
        dataclasses.replace(
            first, result=RuleResult.failed("<script>alert(1)</script>"), fingerprint="h"
        )
    ]
    rendered = render_report("html", hostile)
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;" in rendered
    # No external fetch of any kind: only links a reader clicks, never loads.
    assert not re.search(r"<(script|link|img|iframe)\b", render_report("html", failing))
    assert "@import" not in rendered
    assert "url(http" not in rendered


def test_json_v2_adds_identity_policy_and_target_and_keeps_v1_keys(failing: ScanReport) -> None:
    v1 = json.loads(render_report("json", failing, schema_version=1))
    v2 = json.loads(render_report("json", failing))
    assert v1["schemaVersion"] == 1 and v2["schemaVersion"] == 2
    assert "fingerprint" not in v1["findings"][0]
    for key in v1:
        if key != "schemaVersion":
            assert key in v2
    finding = v2["findings"][0]
    assert re.fullmatch(r"[0-9a-f]{64}", finding["fingerprint"])
    assert finding["verifiedBy"] == "black_box"
    assert v2["target"]["manifestHash"]
    assert v2["target"]["identity"].startswith("http://127.0.0.1")
    assert v2["policy"]["settings"]["timeout"]["source"] == "default"
    assert {r["id"] for r in v2["rules"]} == {f["ruleId"] for f in v2["findings"]}


def test_sarif_carries_the_fingerprint_so_github_can_track_a_finding(failing: ScanReport) -> None:
    sarif = json.loads(render_report("sarif", failing))
    results = sarif["runs"][0]["results"]
    assert all(r["partialFingerprints"]["sentinel/v1"] for r in results)
    assert len({r["partialFingerprints"]["sentinel/v1"] for r in results}) == len(results)


def test_sarif_marks_a_baselined_failure_as_a_suppression_not_a_deletion(
    failing: ScanReport,
) -> None:
    again = copy.copy(failing)
    again.findings = [copy.copy(f) for f in failing.findings]
    from sentinel.triage import apply_baseline

    apply_baseline(again, baseline_mod.create(failing))
    sarif = json.loads(render_report("sarif", again))
    suppressed = [r for r in sarif["runs"][0]["results"] if r.get("suppressions")]
    assert suppressed
    assert all(r["suppressions"][0]["status"] == "accepted" for r in suppressed)
    assert len(sarif["runs"][0]["results"]) == len(failing.findings)


def test_text_report_lists_accepted_failures_separately(failing: ScanReport) -> None:
    again = copy.copy(failing)
    again.findings = [copy.copy(f) for f in failing.findings]
    from sentinel.triage import apply_baseline

    apply_baseline(again, baseline_mod.create(failing))
    text = render_report("text", again)
    assert "ACCEPTED" in text
    assert "FAILING" not in text


def test_a_target_manifest_hash_matches_a_snapshot_of_the_same_server(
    conformant_endpoint: str, clean: ScanReport
) -> None:
    from sentinel import snapshot as snap
    from sentinel.probe.client import Probe

    with Probe(conformant_endpoint) as probe:
        assert snap.capture(probe).manifest_hash == clean.manifest_hash
