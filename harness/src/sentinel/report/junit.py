"""JUnit XML: one `<testcase>` per rule.

INDETERMINATE and NOT_APPLICABLE render as `<skipped>`, never as a pass. That is
the same rule the rest of the harness holds -- an unverifiable MUST scored as a
pass is the fastest way to lose a reviewer's trust -- and JUnit has a `skipped`
element for exactly "this did not run to a verdict". A failure that is waived or
baselined is also `<skipped>`, with the reason, so a CI dashboard shows it without
turning red.
"""

from __future__ import annotations

from xml.etree import ElementTree as ET

from sentinel.catalog.base import Outcome
from sentinel.grade import ScanReport

__all__ = ["render"]


def render(report: ScanReport) -> str:
    gating = [f for f in report.by_outcome(Outcome.FAIL) if not f.suppressed]
    unsettled = (Outcome.INDETERMINATE, Outcome.NOT_APPLICABLE)
    skipped = [f for f in report.findings if f.outcome in unsettled]
    accepted = [f for f in report.by_outcome(Outcome.FAIL) if f.suppressed]
    suite = ET.Element(
        "testsuite",
        {
            "name": f"sentinel · {report.target}",
            "tests": str(len(report.findings)),
            "failures": str(len(gating)),
            "errors": "0",
            "skipped": str(len(skipped) + len(accepted)),
            "time": f"{report.elapsed_s:.3f}",
        },
    )
    props = ET.SubElement(suite, "properties")
    ET.SubElement(props, "property", {"name": "specRevision", "value": report.spec_revision})
    ET.SubElement(props, "property", {"name": "endpoint", "value": report.endpoint})

    for f in report.findings:
        case = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": f.rule.id.rsplit("/", 1)[0],
                "name": f.rule.slug,
                "time": f"{f.elapsed_s:.4f}",
            },
        )
        if f.outcome is Outcome.FAIL and not f.suppressed:
            failure = ET.SubElement(
                case,
                "failure",
                {"message": f.result.detail or f.rule.title, "type": f.rule.severity.value},
            )
            failure.text = f"{f.rule.id}\n{f.result.detail}\nFix: {f.rule.remediation}"
        elif f.outcome is Outcome.FAIL:
            why = (
                f"waived until {f.waived_by.expires_at.isoformat()}: {f.waived_by.reason}"
                if f.waived_by is not None
                else "baselined"
            )
            ET.SubElement(case, "skipped", {"message": f"accepted failure, {why}"})
        elif f.outcome is Outcome.INDETERMINATE:
            ET.SubElement(case, "skipped", {"message": f"indeterminate: {f.result.detail}"})
        elif f.outcome is Outcome.NOT_APPLICABLE:
            ET.SubElement(case, "skipped", {"message": f"not applicable: {f.result.detail}"})
    ET.indent(suite)
    body = ET.tostring(suite, encoding="unicode")
    return f'<?xml version="1.0" encoding="UTF-8"?>\n{body}\n'
