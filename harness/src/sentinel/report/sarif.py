"""SARIF 2.1.0 output.

`docs/HANDOFF.md` §6: SARIF "renders natively in GitHub code scanning, which
makes a scan a first-class CI citizen" — findings appear as annotations rather
than as text somebody has to open a log to read.

Two mappings need stating because SARIF has no vocabulary for either:

* INDETERMINATE becomes a **note** with `"indeterminate"` in its message, never
  a passing result. §8.8 forbids scoring an unverifiable MUST as a pass, and
  SARIF's absence of a "could not determine" level is not a reason to.
* NOT_APPLICABLE is emitted with `kind: "notApplicable"`, which SARIF does have,
  so a rule that did not apply is distinguishable from one that passed.
"""

from __future__ import annotations

from typing import Any

from sentinel import SPEC_REVISION, __version__
from sentinel.catalog.base import Outcome, Severity
from sentinel.grade import ScanReport

SARIF_VERSION = "2.1.0"
SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

#: SARIF levels. A MUST failure is an error; a SHOULD failure is a warning.
LEVEL = {
    (Outcome.FAIL, Severity.MUST): "error",
    (Outcome.FAIL, Severity.SHOULD): "warning",
    (Outcome.FAIL, Severity.MAY): "note",
    (Outcome.INDETERMINATE, Severity.MUST): "note",
    (Outcome.INDETERMINATE, Severity.SHOULD): "note",
    (Outcome.INDETERMINATE, Severity.MAY): "note",
}

KIND = {
    Outcome.PASS: "pass",
    Outcome.FAIL: "fail",
    Outcome.NOT_APPLICABLE: "notApplicable",
    # SARIF has no "could not determine". `informational` is the closest honest
    # mapping: it is explicitly NOT a pass, and the message says why.
    Outcome.INDETERMINATE: "informational",
}


def render(report: ScanReport) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        r = finding.rule
        rules.append(
            {
                "id": r.id,
                "name": r.id.rsplit("/", 1)[-1].replace("-", ""),
                "shortDescription": {"text": r.title},
                "fullDescription": {"text": r.remediation},
                "helpUri": r.citation,
                "help": {"text": f"{r.remediation}\n\nSpecification: {r.citation}"},
                "properties": {
                    "severity": r.severity.value,
                    "verifiability": r.verifiability.value,
                    "specRevision": report.spec_revision,
                },
                "defaultConfiguration": {
                    "level": LEVEL.get((Outcome.FAIL, r.severity), "warning")
                },
            }
        )

        message = finding.result.detail or r.title
        if finding.outcome is Outcome.INDETERMINATE:
            # Spelled out in the message, because a reader scanning GitHub's
            # annotations sees the text before anything else.
            message = f"indeterminate — this scan could not verify this MUST: {message}"

        result: dict[str, Any] = {
            "ruleId": r.id,
            "kind": KIND[finding.outcome],
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": report.endpoint},
                        # SARIF requires a region; the endpoint is not a file,
                        # so line 1 stands for "the target as a whole".
                        "region": {"startLine": 1},
                    }
                }
            ],
            "properties": {
                "outcome": finding.outcome.value,
                "verifiability": r.verifiability.value,
                "remediation": r.remediation,
            },
        }
        # `level` is meaningful only for a failing or informational result;
        # SARIF says it must be absent for kind: pass.
        if finding.outcome in (Outcome.FAIL, Outcome.INDETERMINATE):
            result["level"] = LEVEL[(finding.outcome, r.severity)]

        results.append(result)

    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sentinel",
                        "version": __version__,
                        "informationUri": "https://github.com/patsypppe/sentinel",
                        "semanticVersion": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"sentinel scan --endpoint {report.endpoint}",
                        "properties": {"specRevision": SPEC_REVISION},
                    }
                ],
                "properties": {
                    "summary": {
                        "must": report.counts(Severity.MUST),
                        "should": report.counts(Severity.SHOULD),
                    }
                },
            }
        ],
    }
