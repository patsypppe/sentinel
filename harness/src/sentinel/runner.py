"""One target, one scan, one verdict.

`sentinel scan` and the fleet sweep both go through here, so a target scanned as
part of a fleet is graded by exactly the same code as one scanned by hand.
"""

from __future__ import annotations

import datetime
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from sentinel.baseline import Baseline
from sentinel.budget import BudgetPolicy
from sentinel.catalog.base import Severity
from sentinel.config import Policy, today
from sentinel.grade import BEYOND_SPEC_CATEGORIES, Gate, ScanReport, run_scan
from sentinel.graybox import Evidence
from sentinel.snapshot import Snapshot
from sentinel.triage import apply_policy, effective_registry
from sentinel.waivers import ConfigError

__all__ = ["ScanOptions", "parse_gate", "scan_target"]


def parse_gate(text: str | None) -> Gate | None:
    """`must` / `should` for conformance, or a beyond-spec category by name."""
    if text is None:
        return None
    chosen = text.lower()
    if chosen in BEYOND_SPEC_CATEGORIES:
        # A beyond-spec gate is opt-in by name and never considers a spec rule,
        # so a build that goes red under `--gate ops` is making an operational
        # claim and cannot be mistaken for a conformance one.
        return Gate.beyond(chosen)
    try:
        return Gate.spec(Severity(chosen))
    except ValueError:
        raise ConfigError(
            f"gate {text!r} is not a gate; use 'must' or 'should' for conformance, or "
            + ", ".join(repr(c) for c in BEYOND_SPEC_CATEGORIES)
            + " for a beyond-spec check"
        ) from None


@dataclass(slots=True)
class ScanOptions:
    endpoint: str
    policy: Policy
    token: str | None = None
    verify: bool | str = True
    proxy: str | None = None
    client_cert: str | None = None
    budgets: BudgetPolicy = field(default_factory=BudgetPolicy)
    baseline: Baseline | None = None
    snapshot: Snapshot | None = None
    target_name: str | None = None
    today: datetime.date | None = None
    context: dict[str, Any] = field(default_factory=dict)
    #: False disables every command-shaped gray-box evidence kind (`--no-exec`).
    allow_exec: bool = True
    #: The environment gray-box token variables are read from.
    env: Mapping[str, str] | None = None


def scan_target(options: ScanOptions) -> ScanReport:
    """Scan one endpoint under a policy and return the triaged report."""
    policy = options.policy
    context: dict[str, Any] = dict(options.context)
    if options.snapshot is not None:
        context["snapshot"] = options.snapshot
    if policy.graybox:
        context["graybox"] = policy.graybox
        context["evidence"] = Evidence(
            config=policy.graybox,
            env=os.environ if options.env is None else options.env,
            allow_exec=options.allow_exec,
        )
    report = run_scan(
        options.endpoint,
        registry=effective_registry(policy),
        timeout=policy.timeout,
        bearer_token=options.token,
        include_deprecated=policy.include_deprecated,
        verify=options.verify,
        proxy=options.proxy,
        client_cert=options.client_cert,
        retries=policy.retries,
        budgets=options.budgets,
        safe=policy.safe,
        concurrency=policy.concurrency,
        target_name=options.target_name,
        skip=policy.disabled,
        context=context,
    )
    apply_policy(report, policy, today=options.today or today(), baseline=options.baseline)
    return report
