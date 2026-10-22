"""Waivers: a recorded, expiring decision to live with a finding.

The single worst failure available to a tool like this is converting an
operator's typo into a permanent blind spot. Snyk's `.snyk` file treats a
malformed expiry as "ignore forever". So here `expires_at` is required, a
malformed one is a hard error, and a waiver past its date does not quietly stop
applying: the finding it covered re-fails, loudly, and is labelled expired.
"""

from __future__ import annotations

import datetime
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sentinel.fingerprint import target_identity

__all__ = ["EXPIRY_WARNING_DAYS", "ConfigError", "Waiver", "parse_waiver"]

#: A waiver this close to its date is reported as expiring soon.
EXPIRY_WARNING_DAYS = 14


class ConfigError(ValueError):
    """The policy is unusable. Always a harness error, never a verdict."""


@dataclass(frozen=True, slots=True)
class Waiver:
    rule: str
    reason: str
    expires_at: datetime.date
    #: None applies to every target; otherwise an endpoint URL or a fleet target
    #: name, compared after normalisation.
    endpoint: str | None = None
    approved_by: str = ""

    def matches(self, rule_id: str, endpoint: str, name: str | None) -> bool:
        if self.rule != rule_id:
            return False
        if self.endpoint is None:
            return True
        return self.endpoint == name or target_identity(self.endpoint) == target_identity(endpoint)

    def expired(self, today: datetime.date) -> bool:
        return today > self.expires_at

    def expiring_soon(self, today: datetime.date) -> bool:
        return not self.expired(today) and (self.expires_at - today).days <= EXPIRY_WARNING_DAYS


def _parse_date(value: Any, where: str) -> datetime.date:
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    if isinstance(value, str):
        try:
            return datetime.date.fromisoformat(value)
        except ValueError:
            pass
    raise ConfigError(
        f"{where}: expires_at {value!r} is not a date. Use YYYY-MM-DD (for example "
        "2026-11-30). A waiver whose expiry cannot be read is rejected rather than "
        "treated as permanent."
    )


def parse_waiver(raw: Mapping[str, Any], index: int) -> Waiver:
    where = f"waivers[{index}]"
    for required in ("rule", "reason", "expires_at"):
        if required not in raw:
            raise ConfigError(
                f"{where}: missing {required!r}. A waiver names the rule, says why, and "
                "says when it stops applying."
            )
    reason = str(raw["reason"]).strip()
    if len(reason) < 10:
        raise ConfigError(f"{where}: reason is too short to be a reason ({reason!r})")
    unknown = set(raw) - {"rule", "reason", "expires_at", "endpoint", "approved_by"}
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {sorted(unknown)}")
    endpoint = raw.get("endpoint")
    return Waiver(
        rule=str(raw["rule"]),
        reason=reason,
        expires_at=_parse_date(raw["expires_at"], where),
        endpoint=None if endpoint is None else str(endpoint),
        approved_by=str(raw.get("approved_by", "")),
    )
