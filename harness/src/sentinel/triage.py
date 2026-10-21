"""Turning raw findings into a verdict a team can live with.

A scanner that reports every finding every time, forever, is a scanner teams
route around. Three mechanisms keep it usable without ever hiding a finding:

* **Waivers** acknowledge a failure for a bounded time, with a reason.
* **Baselines** acknowledge everything that failed when the scanner was adopted,
  so the gate fires only on what is new.
* **Severity overrides** let a company be stricter than the specification.

None of them removes a finding from the report. A waived failure is listed as
waived; a baselined failure is listed as baselined; a baseline entry that now
passes is listed as fixed. A baseline that only ever grows is how a tool becomes
something teams ignore, so what has been *fixed* is always shown.
"""

from __future__ import annotations

import dataclasses
import datetime
from collections.abc import Iterable

from sentinel.baseline import Baseline
from sentinel.catalog.base import REGISTRY, Outcome, Registry
from sentinel.config import Policy
from sentinel.grade import ScanReport
from sentinel.waivers import Waiver

__all__ = ["apply_baseline", "apply_policy", "apply_waivers", "effective_registry"]


def effective_registry(policy: Policy, registry: Registry | None = None) -> Registry:
    """The catalog as this policy sees it: overrides applied, nothing removed.

    A severity override swaps the rule's severity and nothing else; its id keeps
    the severity it was published with, because ids are permanent. Disabled rules
    stay in the registry and are skipped at scan time, so the report can list
    them.
    """
    base = registry if registry is not None else REGISTRY
    derived = Registry()
    for rule in base.all(include_deprecated=True):
        override = policy.severity_overrides.get(rule.id)
        derived.register(dataclasses.replace(rule, severity=override) if override else rule)
    return derived


def apply_waivers(
    report: ScanReport, waivers: Iterable[Waiver], today: datetime.date
) -> None:
    """Attach waivers to the findings they cover, and note the housekeeping.

    An expired waiver does not apply: the finding stays a failure, is labelled,
    and the report says which waiver lapsed and when.
    """
    waivers = list(waivers)
    used: set[Waiver] = set()
    for finding in report.findings:
        if finding.outcome is not Outcome.FAIL:
            continue
        for waiver in waivers:
            if not waiver.matches(finding.rule.id, report.endpoint, report.target_name):
                continue
            used.add(waiver)
            if waiver.expired(today):
                finding.waiver_expired = waiver
            else:
                finding.waived_by = waiver
                finding.waiver_expired = None
                break

    for waiver in waivers:
        applies_here = waiver.endpoint is None or waiver.matches(
            waiver.rule, report.endpoint, report.target_name
        )
        if not applies_here:
            continue
        label = f"{waiver.rule} (expires {waiver.expires_at.isoformat()})"
        if waiver.expired(today):
            report.waiver_notes.append(f"EXPIRED waiver, no longer applies: {label}")
        elif waiver not in used:
            report.waiver_notes.append(
                f"unused waiver, the rule is not failing: {label}. Remove it."
            )
        elif waiver.expiring_soon(today):
            days = (waiver.expires_at - today).days
            report.waiver_notes.append(f"waiver expires in {days} day(s): {label}")


def apply_baseline(report: ScanReport, baseline: Baseline) -> None:
    """Mark known failures baselined; list what was fixed and what is new."""
    failing = {f.fingerprint for f in report.findings if f.outcome is Outcome.FAIL}
    known = set(baseline.fingerprints)
    for finding in report.findings:
        if finding.outcome is not Outcome.FAIL:
            continue
        if finding.fingerprint in known:
            finding.baselined = True
        elif finding.rule.id not in baseline.rule_ids:
            # The rule did not exist when the baseline was taken, so this failure
            # cannot have been accepted. It is new, and it says why.
            finding.rule_is_new = True
    report.fixed = sorted(known - failing)


def apply_policy(
    report: ScanReport,
    policy: Policy,
    *,
    today: datetime.date,
    baseline: Baseline | None = None,
) -> None:
    report.policy = policy.describe()
    apply_waivers(report, policy.waivers, today)
    if baseline is not None:
        apply_baseline(report, baseline)
