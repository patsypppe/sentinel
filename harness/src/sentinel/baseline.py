"""Baselines: adopt the scanner without fixing everything first.

    sentinel baseline create --endpoint URL --out sentinel-baseline.json
    sentinel scan --endpoint URL --baseline sentinel-baseline.json --gate must

With a baseline the gate fires only on fingerprints it has not seen. The file
records which catalog it was taken against: scanning with a newer catalog reports
a rule that did not exist at baseline time as new, and says so, because a
baseline cannot have accepted a rule that was not written yet.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel import SPEC_REVISION, __version__
from sentinel.catalog.base import Outcome
from sentinel.grade import ScanReport
from sentinel.waivers import ConfigError

__all__ = ["Baseline", "create", "load", "prune", "save"]

SCHEMA_VERSION = 1


@dataclass(slots=True)
class Baseline:
    target: str
    spec_revision: str
    sentinel_version: str
    created_at: str
    #: Every rule id that was evaluated when the baseline was taken.
    rule_ids: list[str] = field(default_factory=list)
    #: fingerprint -> what it was, so the file is reviewable in a pull request.
    entries: dict[str, dict[str, str]] = field(default_factory=dict)

    @property
    def fingerprints(self) -> list[str]:
        return sorted(self.entries)


def create(report: ScanReport) -> Baseline:
    """A baseline of every failure in `report`."""
    entries = {
        f.fingerprint: {"ruleId": f.rule.id, "detail": f.result.detail[:200]}
        for f in report.findings
        if f.outcome is Outcome.FAIL
    }
    return Baseline(
        target=report.target,
        spec_revision=report.spec_revision,
        sentinel_version=__version__,
        created_at=datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        rule_ids=sorted(f.rule.id for f in report.findings),
        entries=entries,
    )


def prune(baseline: Baseline, report: ScanReport) -> tuple[Baseline, list[str]]:
    """Drop entries that no longer fail. Returns the new baseline and what left."""
    failing = {f.fingerprint for f in report.findings if f.outcome is Outcome.FAIL}
    kept = {fp: entry for fp, entry in baseline.entries.items() if fp in failing}
    dropped = sorted(set(baseline.entries) - set(kept))
    pruned = Baseline(
        target=baseline.target,
        spec_revision=baseline.spec_revision,
        sentinel_version=baseline.sentinel_version,
        created_at=baseline.created_at,
        rule_ids=baseline.rule_ids,
        entries=kept,
    )
    return pruned, dropped


def save(baseline: Baseline, path: Path) -> None:
    payload: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "target": baseline.target,
        "specRevision": baseline.spec_revision,
        "sentinelVersion": baseline.sentinel_version,
        "createdAt": baseline.created_at,
        "ruleIds": baseline.rule_ids,
        "findings": [
            {"fingerprint": fp, **baseline.entries[fp]} for fp in sorted(baseline.entries)
        ],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n")


def load(path: Path) -> Baseline:
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"baseline {path} cannot be read: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schemaVersion") != SCHEMA_VERSION:
        raise ConfigError(
            f"baseline {path} is not a schemaVersion {SCHEMA_VERSION} baseline; "
            "recreate it with `sentinel baseline create`"
        )
    if raw.get("specRevision") != SPEC_REVISION:
        raise ConfigError(
            f"baseline {path} was taken against MCP {raw.get('specRevision')}, and this "
            f"catalog grades {SPEC_REVISION}. A baseline cannot carry across a spec "
            "revision: rule ids embed the revision. Recreate it."
        )
    entries = {
        str(item["fingerprint"]): {
            "ruleId": str(item.get("ruleId", "")),
            "detail": str(item.get("detail", "")),
        }
        for item in raw.get("findings", [])
    }
    return Baseline(
        target=str(raw.get("target", "")),
        spec_revision=str(raw["specRevision"]),
        sentinel_version=str(raw.get("sentinelVersion", "")),
        created_at=str(raw.get("createdAt", "")),
        rule_ids=[str(i) for i in raw.get("ruleIds", [])],
        entries=entries,
    )
