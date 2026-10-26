"""The machine-readable scan report."""

from __future__ import annotations

from typing import Any

from sentinel.catalog.base import Outcome, Severity
from sentinel.grade import ScanReport


def render(
    report: ScanReport, *, schema_version: int = 2, gate: dict[str, Any] | None = None
) -> dict[str, Any]:
    """A stable JSON shape. `schema_version=1` re-emits the original, for one more
    minor release, so a consumer pinned to it keeps working.

    `schemaVersion` is here from the first release. A report format that changes
    without saying so silently breaks whatever was parsing it.
    """
    if schema_version == 1:
        return _render_v1(report)
    payload = _render_v2(report)
    if gate is not None:
        payload["gate"] = gate
    return payload


def _waiver(w: object) -> dict[str, Any] | None:
    from sentinel.waivers import Waiver

    if not isinstance(w, Waiver):
        return None
    return {
        "rule": w.rule,
        "reason": w.reason,
        "expiresAt": w.expires_at.isoformat(),
        "approvedBy": w.approved_by,
    }


def _render_v2(report: ScanReport) -> dict[str, Any]:
    """Additive over v1: every v1 key is still here, unchanged."""
    from sentinel.catalog.base import REGISTRY

    payload = _render_v1(report)
    payload["schemaVersion"] = 2
    payload["target"] = {
        "endpoint": report.endpoint,
        "name": report.target_name,
        "identity": report.target,
        "manifestHash": report.manifest_hash,
        "generation": report.generation,
    }
    payload["policy"] = report.policy
    suppressed = [f for f in report.findings if f.suppressed]
    payload["summary"]["gating"] = {
        "failing": sum(1 for f in report.findings if f.outcome is Outcome.FAIL),
        "waived": sum(1 for f in suppressed if f.waived_by is not None),
        "baselined": sum(1 for f in suppressed if f.baselined),
        "expiredWaivers": sum(1 for f in report.findings if f.waiver_expired is not None),
    }
    for entry, finding in zip(payload["findings"], report.findings, strict=True):
        entry["fingerprint"] = finding.fingerprint
        entry["evidenceKey"] = finding.rule.evidence_key
        entry["verifiedBy"] = finding.verified_by
        entry["waivedBy"] = _waiver(finding.waived_by)
        entry["waiverExpired"] = _waiver(finding.waiver_expired)
        entry["baselined"] = finding.baselined
        entry["ruleIsNewSinceBaseline"] = finding.rule_is_new
    payload["fixed"] = report.fixed
    payload["waiverNotes"] = report.waiver_notes
    # The catalog as evaluated, so an archived report stays interpretable after
    # the catalog moves on.
    payload["rules"] = [
        {
            "id": r.id,
            "severity": r.severity.value,
            "introducedIn": r.introduced_in,
            "deprecatedIn": r.deprecated_in,
            "supersededBy": r.superseded_by,
        }
        for r in REGISTRY.all(include_deprecated=True)
        if r.id in {f.rule.id for f in report.findings}
    ]
    return payload


def _render_v1(report: ScanReport) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "tool": "sentinel",
        "specRevision": report.spec_revision,
        "endpoint": report.endpoint,
        "startedAt": report.started_at,
        "elapsedSeconds": round(report.elapsed_s, 3),
        # Additive, so schemaVersion stays 1: a consumer that ignores these keys
        # reads every other field exactly as before.
        "safeMode": report.safe,
        "skippedInSafeMode": len(report.skipped_for_safety),
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
                # The lifecycle travels with the finding. A consumer diffing two
                # archived reports has to be able to tell "this rule was retired"
                # from "this rule stopped failing", and a namespace tells it
                # whether the finding was ever a conformance claim at all.
                "namespace": f.rule.namespace.value,
                "deprecated": bool(f.rule.deprecated_in),
                "supersededBy": f.rule.superseded_by,
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
