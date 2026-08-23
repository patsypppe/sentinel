"""The machine-readable scan report."""

from __future__ import annotations

from typing import Any

from sentinel.catalog.base import Outcome, Severity
from sentinel.grade import ScanReport


def render(report: ScanReport) -> dict[str, Any]:
    """A stable JSON shape.

    `schemaVersion` is here from the first release. A report format that changes
    without saying so silently breaks whatever was parsing it.
    """
    return {
        "schemaVersion": 1,
        "tool": "sentinel",
        "specRevision": report.spec_revision,
        "endpoint": report.endpoint,
        "startedAt": report.started_at,
        "elapsedSeconds": round(report.elapsed_s, 3),
        "summary": {
            "must": report.counts(Severity.MUST),
            "should": report.counts(Severity.SHOULD),
            "total": report.counts(),
        },
        "findings": [
            {
                "ruleId": f.rule.id,
                "title": f.rule.title,
                "severity": f.rule.severity.value,
                "verifiability": f.rule.verifiability.value,
                "citation": f.rule.citation,
                "outcome": f.outcome.value,
                "detail": f.result.detail,
                "evidence": f.result.evidence,
                # Carried on every finding, not only failures: a report consumed
                # by a tool should not have to look the fix up elsewhere.
                "remediation": f.rule.remediation,
                "elapsedSeconds": round(f.elapsed_s, 4),
            }
            for f in report.findings
        ],
        # Its own key, so a consumer cannot mistake these for passes. §8.8:
        # "Report them in their own bucket, exclude them from the gate."
        "unverifiable": [
            {"ruleId": f.rule.id, "why": f.result.detail}
            for f in report.findings
            if f.outcome is Outcome.INDETERMINATE
        ],
    }
