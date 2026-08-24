"""SARIF 2.1.0 output.

`docs/HANDOFF.md` §6: SARIF "renders natively in GitHub code scanning, which
makes a scan a first-class CI citizen" — findings appear as annotations rather
than as text somebody has to open a log to read.

**Locations.** A conformance finding is about a running SERVICE, not a line in a
file, and SARIF's location model assumes files. GitHub code scanning enforces
that assumption strictly — it rejects a document whose `artifactLocation.uri`
scheme does not match the checkout's:

    SARIF URI scheme "http" did not match the checkout URI scheme "file"

So each result carries both. The endpoint goes in `logicalLocations`, which is
SARIF's own vocabulary for a subject that is not a file, and in the message. The
`physicalLocation` is an ANCHOR: a repo-relative path chosen by the caller,
which is what GitHub attaches the annotation to. It does not claim the finding
is caused by that line — it says "this is the file to open about it" — and the
anchor is a parameter precisely because only the caller knows what that is. A
scan of a third-party server has no such file, and should use `--format json`.

Two more mappings need stating because SARIF has no vocabulary for either:

* INDETERMINATE becomes a **note** with `"indeterminate"` in its message, never
  a passing result. §8.8 forbids scoring an unverifiable MUST as a pass, and
  SARIF's absence of a "could not determine" level is not a reason to.
* NOT_APPLICABLE is emitted with `kind: "notApplicable"`, which SARIF does have,
  so a rule that did not apply is distinguishable from one that passed.
"""

from __future__ import annotations

from typing import Any

from sentinel import SPEC_REVISION, __version__
from sentinel.catalog.base import Namespace, Outcome, Severity
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


#: Where an annotation attaches when the caller does not say.
#:
#: README.md, because a reader who lands on an annotation with no idea what
#: "MCP/2026-07-28/MUST/…" means needs the project's front door, not a source
#: file that happens to be nearby.
DEFAULT_ANCHOR = "README.md"


def render(report: ScanReport, *, anchor: str = DEFAULT_ANCHOR) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        r = finding.rule
        properties: dict[str, Any] = {
            "severity": r.severity.value,
            "verifiability": r.verifiability.value,
            "specRevision": report.spec_revision,
            "namespace": r.namespace.value,
            "deprecated": r.is_deprecated,
        }
        if r.superseded_by:
            properties["supersededBy"] = r.superseded_by

        entry: dict[str, Any] = {
            "id": r.id,
            "name": r.id.rsplit("/", 1)[-1].replace("-", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.remediation},
            "properties": properties,
            "defaultConfiguration": {
                "level": LEVEL.get((Outcome.FAIL, r.severity), "warning")
            },
        }

        if r.namespace is Namespace.MCP:
            entry["helpUri"] = r.citation
            entry["help"] = {"text": f"{r.remediation}\n\nSpecification: {r.citation}"}
        else:
            # A beyond-spec rule has nothing to cite. Emitting helpUri "" and a
            # bare "Specification: " with nothing after it is a citation
            # pointing at nothing -- which is the failure the SENTINEL
            # namespace exists to prevent, so it must not be reintroduced here.
            entry["help"] = {"text": f"{r.remediation}\n\nRationale: {r.rationale}"}

        rules.append(entry)

        # The endpoint is named in the message because the annotation view
        # shows the message and the anchored file, and nothing else.
        message = f"[{report.endpoint}] " + (finding.result.detail or r.title)
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
                    # The anchor, so GitHub has a file to attach the annotation
                    # to. Line 1 stands for "the target as a whole"; nothing
                    # here claims the finding is caused by that line.
                    "physicalLocation": {
                        "artifactLocation": {"uri": anchor},
                        "region": {"startLine": 1},
                    },
                    # The real subject. SARIF has this vocabulary exactly for
                    # findings that are not about a file.
                    "logicalLocations": [
                        {
                            "name": report.endpoint,
                            "kind": "resource",
                            "fullyQualifiedName": f"{report.endpoint}#{r.id}",
                        }
                    ],
                }
            ],
            "properties": {
                "outcome": finding.outcome.value,
                "verifiability": r.verifiability.value,
                "remediation": r.remediation,
                # Repeated here so a consumer that ignores logicalLocations —
                # and GitHub's annotation view does — can still tell which
                # target a finding is about.
                "endpoint": report.endpoint,
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
