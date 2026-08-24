"""The deprecation inventory (`SN-CAP-29`).

`docs/HANDOFF.md` §10 (WP-11): detect which deprecated features a target still
depends on, and report each with the date the registry says it was deprecated
and the removal condition the registry states — which is not always a date.

    "Say 'on or after'; the window is a minimum, not a schedule."

That phrasing is load-bearing. A date presented as a deadline gets put in a plan
and treated as the moment the feature stops working. The specification promises
a *minimum* notice period, which means the feature may last longer — and that a
migration finished the week before is not late, it is finished.

The same discipline forbids inventing the date the registry declines to give.
Two of the six windows are not date arithmetic: includeContext's follows
Sampling's, and HTTP+SSE's is three months after SEP-2596 reaches Final, an
event that has not happened. `AfterEvent` therefore has no date and no way to
be asked for one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum

from sentinel import SPEC_REVISION
from sentinel.catalog.base import SPEC_BASE
from sentinel.probe.client import Probe

#: The revision this harness grades against, and the date on which SEP-2577 and
#: PR #2858 deprecated four of the six features below. It is NOT a default for
#: the other two: the registry deprecated `includeContext` on 2025-11-25 and
#: HTTP+SSE on 2025-03-26, and each feature carries its own date.
DEPRECATED_ON = date(2026, 7, 28)

#: The specification's minimum notice period before a deprecated feature may be
#: removed. Twelve months, per the 2026 roadmap.
MINIMUM_NOTICE_MONTHS = 12


class Confidence(StrEnum):
    #: The server answered in a way only a server implementing the feature
    #: would.
    OBSERVED = "observed"
    #: The server advertises it, but the behaviour was not exercised.
    ADVERTISED = "advertised"
    #: The feature could not be probed from the wire at all.
    UNKNOWN = "unknown"


def earliest_removal(deprecated_on: date = DEPRECATED_ON) -> date:
    """Deprecation date + the minimum notice period.

    Kept as a function so the arithmetic is stated once. `dateutil` would do
    this in one line and is not worth a dependency for one call.
    """
    month = deprecated_on.month + MINIMUM_NOTICE_MONTHS
    year = deprecated_on.year + (month - 1) // 12
    month = (month - 1) % 12 + 1
    day = min(deprecated_on.day, _days_in_month(year, month))
    return date(year, month, day)


def _days_in_month(year: int, month: int) -> int:
    import calendar

    return calendar.monthrange(year, month)[1]


@dataclass(frozen=True, slots=True)
class FixedRevision:
    """The registry names a date: "First revision released on or after X"."""

    on_or_after: date

    def describe(self) -> str:
        return f"the first revision released on or after {self.on_or_after.isoformat()}"


@dataclass(frozen=True, slots=True)
class FollowsFeature:
    """The registry ties this feature's window to another's."""

    feature_id: str
    sep: str = ""

    def describe(self) -> str:
        tail = f" ({self.sep})" if self.sep else ""
        return f"whenever {self.feature_id} is removable{tail}"


@dataclass(frozen=True, slots=True)
class AfterEvent:
    """The registry ties the window to an event that has not happened.

    There is deliberately no date here, and no way to ask for one. A migration
    report that prints a number it cannot know is worse than one that prints the
    condition — the number gets put in a plan and treated as a deadline.
    """

    description: str
    sep: str = ""

    def describe(self) -> str:
        return self.description


RemovalWindow = FixedRevision | FollowsFeature | AfterEvent


#: Keyword-only so `deprecated_on` and `removal` can be required without
#: reordering the fields around the defaulted ones. Every construction below is
#: already keyword-form, so nothing else moves.
@dataclass(slots=True, kw_only=True)
class DeprecatedFeature:
    id: str
    name: str
    #: What replaced it. A finding that only says "this is deprecated" leaves
    #: the reader to work out the migration themselves.
    replacement: str
    citation: str
    #: The date the registry says this feature was deprecated. Required: the
    #: six features were deprecated on three different dates, and a default
    #: here is how four right answers and two wrong ones get shipped together.
    deprecated_on: date
    #: The condition the registry states for the earliest removal. Not always a
    #: date — see `AfterEvent`.
    removal: RemovalWindow
    #: The SEP that deprecated it, where there is one.
    sep: str = ""
    note: str = ""


def resolve_removal(
    feature: DeprecatedFeature,
    by_id: dict[str, DeprecatedFeature] | None = None,
) -> FixedRevision | AfterEvent:
    """Follow FollowsFeature to the window that actually decides the date."""
    table = by_id if by_id is not None else FEATURES_BY_ID
    seen: set[str] = set()
    window: RemovalWindow = feature.removal
    while isinstance(window, FollowsFeature):
        if window.feature_id in seen:
            return AfterEvent(
                f"a cycle in the registry's follows-chain at {window.feature_id}"
            )
        seen.add(window.feature_id)
        followed = table.get(window.feature_id)
        if followed is None:
            return AfterEvent(f"whenever {window.feature_id} is removable")
        window = followed.removal
    return window


@dataclass(slots=True)
class Detection:
    feature: DeprecatedFeature
    in_use: bool
    confidence: Confidence
    evidence: str = ""


@dataclass(slots=True)
class Inventory:
    endpoint: str
    as_of: date
    detections: list[Detection] = field(default_factory=list)

    @property
    def in_use(self) -> list[Detection]:
        return [d for d in self.detections if d.in_use]

    def months_remaining(self, detection: Detection) -> int | None:
        """Whole months until the earliest removal, or None if it is not a date.

        Negative once the window has passed — the feature may already have been
        removed, and reporting a negative number is more useful than clamping to
        zero and implying there is still time. `None` means the registry ties the
        window to an event rather than a date, and no number is honest.
        """
        window = resolve_removal(detection.feature)
        if not isinstance(window, FixedRevision):
            return None
        removal = window.on_or_after
        return (removal.year - self.as_of.year) * 12 + (removal.month - self.as_of.month)


#: SEP-2577 and PR #2858 share a window: the first revision released on or after
#: 2027-07-28. Stated once so the four features that share it cannot drift.
_SEP_2577 = FixedRevision(date(2027, 7, 28))

#: The five features §10 (WP-11) names, plus the includeContext values.
#:
#: Dates and removal conditions are transcribed from the registry's deprecation
#: page — see `tests/harness/data/deprecation_registry.json`, which holds the
#: same rows verbatim and fails a test if these drift from them.
FEATURES: list[DeprecatedFeature] = [
    DeprecatedFeature(
        id="roots",
        name="Roots",
        replacement="explicit tool arguments naming the paths a tool may touch",
        citation=f"{SPEC_BASE}/changelog#sep-2577-roots-sampling-logging",
        sep="SEP-2577",
        deprecated_on=date(2026, 7, 28),
        removal=_SEP_2577,
        note=(
            "Roots let a server ask the client which filesystem locations it may use. In a "
            "stateless protocol there is no session to hold that answer, and a tool that "
            "needs a path should take one."
        ),
    ),
    DeprecatedFeature(
        id="sampling",
        name="Sampling",
        replacement="multi round-trip requests (resultType: input_required)",
        citation=f"{SPEC_BASE}/changelog#sep-2577-roots-sampling-logging",
        sep="SEP-2577",
        deprecated_on=date(2026, 7, 28),
        removal=_SEP_2577,
        note=(
            "Sampling was the server calling the client to ask a model for a completion. "
            "The server never initiates in this revision, so the whole direction is gone."
        ),
    ),
    DeprecatedFeature(
        id="logging",
        name="Logging",
        replacement="_meta.io.modelcontextprotocol/logLevel, set per request",
        citation=f"{SPEC_BASE}/changelog#sep-2577-roots-sampling-logging",
        sep="SEP-2577",
        deprecated_on=date(2026, 7, 28),
        removal=_SEP_2577,
        note=(
            "logging/setLevel set a level for a session. There are no sessions, so the "
            "level travels with each request instead."
        ),
    ),
    DeprecatedFeature(
        id="http-sse",
        name="HTTP+SSE transport",
        replacement="Streamable HTTP",
        citation=f"{SPEC_BASE}/basic/transports#streamable-http",
        sep="SEP-2596",
        deprecated_on=date(2025, 3, 26),
        # No date, and no way to ask for one. SEP-2596 has not reached Final,
        # so the three months have not started.
        removal=AfterEvent(
            "three months after SEP-2596 reaches Final", sep="SEP-2596"
        ),
        note=(
            "The two-endpoint SSE transport required a server-held connection. Streamable "
            "HTTP is one POST endpoint, which is what lets a gateway route on headers."
        ),
    ),
    DeprecatedFeature(
        id="oauth-dcr",
        name="OAuth Dynamic Client Registration",
        replacement="Client ID Metadata Documents (CIMD)",
        citation=f"{SPEC_BASE}/basic/authorization#client-registration",
        sep="PR #2858",
        deprecated_on=date(2026, 7, 28),
        removal=_SEP_2577,
        note=(
            "DCR let any client mint its own registration. CIMD makes a client's identity "
            "a document at a URL the authorization server can fetch and check."
        ),
    ),
    DeprecatedFeature(
        id="include-context",
        name='includeContext: "thisServer" / "allServers"',
        replacement="explicit arguments carrying whatever context the call needs",
        citation=f"{SPEC_BASE}/changelog#includecontext",
        sep="SEP-2596",
        deprecated_on=date(2025, 11, 25),
        # The registry says "Follows Sampling (SEP-2577)" — not a date of its
        # own, and not the twelve months from its own deprecation date either.
        removal=FollowsFeature(feature_id="sampling", sep="SEP-2577"),
        note=(
            'Both values asked the client to gather context on the server\'s behalf. '
            '"allServers" additionally leaked one server\'s context to another.'
        ),
    ),
]

FEATURES_BY_ID = {f.id: f for f in FEATURES}


def _method_is_implemented(
    probe: Probe,
    method: str,
    params: dict[str, object] | None = None,
    *,
    signature_keys: tuple[str, ...] = (),
) -> tuple[bool, Confidence, str]:
    """Whether a server implements a method, controlling for a catch-all.

    Three outcomes, not two. A server that answers everything answers this too,
    and calling that "in use" would report a deprecation nobody has. Calling it
    "not in use" would be equally wrong — the feature might be there. So:

    * method-not-found, or an error: NOT in use, observed.
    * a result that an invented method name does NOT also get: in use, observed.
    * a result the invented name gets too, but carrying a field only this
      feature produces (`roots`, `role`): in use, observed — the shape is the
      evidence the control could not supply.
    * a result indistinguishable from the catch-all: UNKNOWN. Reported as not
      in use, and flagged, because "I could not tell" is the honest answer and
      an inventory that quietly guesses is worse than one that says so.
    """
    resp = probe.call(method, params or {})
    if resp.error_code() == -32601:
        return False, Confidence.OBSERVED, f"{method} → method-not-found"
    if resp.result() is None:
        return False, Confidence.OBSERVED, f"{method} → {resp.error()}"

    control = probe.call("sentinel/definitely-not-a-real-method", {})
    if control.result() is None:
        return True, Confidence.OBSERVED, f"{method} returned a result; an unknown method did not"

    result = resp.result() or {}
    present = [k for k in signature_keys if k in result]
    if present:
        return True, Confidence.OBSERVED, (
            f"{method} returned a result carrying {present}, which only this feature "
            "produces — an invented method name got a result too, but not that shape"
        )

    return False, Confidence.UNKNOWN, (
        f"{method} returned a result, but so did an invented method name and the "
        "response carries nothing specific to this feature. This server answers "
        "everything, so its use of the feature could not be determined."
    )


def detect(probe: Probe) -> list[Detection]:
    """Probe for each deprecated feature."""
    detections: list[Detection] = []

    # Roots — the server asking the client for filesystem locations.
    used, confidence, evidence = _method_is_implemented(
        probe, "roots/list", signature_keys=("roots",)
    )
    detections.append(Detection(FEATURES_BY_ID["roots"], used, confidence, evidence))

    # Sampling — the server calling the client for a completion.
    used, confidence, evidence = _method_is_implemented(
        probe, "sampling/createMessage", {"messages": [], "maxTokens": 1},
        signature_keys=("role", "content", "stopReason", "model"),
    )
    detections.append(Detection(FEATURES_BY_ID["sampling"], used, confidence, evidence))

    # Logging — a session-scoped log level.
    #
    # No signature keys: a conformant logging/setLevel returns an EMPTY result,
    # so on a server that answers everything there is genuinely nothing to tell
    # it apart by, and this reports UNKNOWN rather than inventing a verdict.
    used, confidence, evidence = _method_is_implemented(
        probe, "logging/setLevel", {"level": "info"}
    )
    detections.append(Detection(FEATURES_BY_ID["logging"], used, confidence, evidence))

    detections.append(_detect_http_sse(probe))
    detections.append(_detect_oauth_dcr(probe))
    detections.append(_detect_include_context(probe))

    return detections


def _detect_http_sse(probe: Probe) -> Detection:
    """HTTP+SSE announces itself in what a server advertises and how it replies."""
    resp = probe.discover()

    content_type = resp.headers.get("content-type", "")
    if "text/event-stream" in content_type:
        return Detection(
            FEATURES_BY_ID["http-sse"], True, Confidence.OBSERVED,
            f"the endpoint replied with Content-Type: {content_type}",
        )

    result = resp.result() or {}
    for key in ("transports", "transport", "endpoints"):
        value = result.get(key)
        if isinstance(value, (list, str)) and "sse" in str(value).lower():
            return Detection(
                FEATURES_BY_ID["http-sse"], True, Confidence.ADVERTISED,
                f"server/discover advertises {key} = {value!r}",
            )

    return Detection(
        FEATURES_BY_ID["http-sse"], False, Confidence.OBSERVED,
        "the endpoint replies as Streamable HTTP and advertises no SSE transport",
    )


def _detect_oauth_dcr(probe: Probe) -> Detection:
    """DCR is advertised in authorization-server metadata.

    The probe cannot fetch that metadata — it may be on a different host, and
    following a link a scan target supplied is exactly the SSRF the security
    page warns about. So this reports what the SERVER says, and says which it is.
    """
    result = probe.discover().result() or {}

    for key in ("authorization", "auth", "oauth"):
        value = result.get(key)
        if isinstance(value, dict):
            markers = (
                "registration_endpoint",
                "registrationEndpoint",
                "dynamicClientRegistration",
            )
            for marker in markers:
                if marker in value:
                    return Detection(
                        FEATURES_BY_ID["oauth-dcr"], True, Confidence.ADVERTISED,
                        f"server/discover advertises {key}.{marker}",
                    )

    return Detection(
        FEATURES_BY_ID["oauth-dcr"], False, Confidence.UNKNOWN,
        "server/discover advertises no dynamic registration endpoint. The authorization "
        "server's own metadata was NOT fetched: it may live on another host, and following "
        "a URL the scan target supplied is the SSRF the security guidance warns about.",
    )


def _detect_include_context(probe: Probe) -> Detection:
    """includeContext appeared in sampling requests, so it goes with sampling."""
    resp = probe.call("sampling/createMessage", {
        "messages": [], "maxTokens": 1, "includeContext": "allServers",
    })
    if resp.result() is not None:
        control = probe.call("sentinel/definitely-not-a-real-method", {})
        if control.result() is None:
            return Detection(
                FEATURES_BY_ID["include-context"], True, Confidence.OBSERVED,
                'sampling/createMessage accepted includeContext: "allServers"',
            )
        result = resp.result() or {}
        if any(k in result for k in ("role", "content", "stopReason", "model")):
            return Detection(
                FEATURES_BY_ID["include-context"], True, Confidence.OBSERVED,
                'sampling/createMessage accepted includeContext: "allServers" and returned '
                "a sampling-shaped result",
            )
        return Detection(
            FEATURES_BY_ID["include-context"], False, Confidence.UNKNOWN,
            "this server answers every method, and its reply to a sampling request "
            "carrying includeContext is indistinguishable from that catch-all",
        )

    return Detection(
        FEATURES_BY_ID["include-context"], False, Confidence.OBSERVED,
        "the server does not accept a sampling request carrying includeContext",
    )


def build_inventory(probe: Probe, as_of: date) -> Inventory:
    return Inventory(endpoint=probe.endpoint, as_of=as_of, detections=detect(probe))


def render_text(inventory: Inventory, *, color: bool = True) -> str:
    """The inventory as a human reads it."""
    reset, bold, dim, red, green = "\033[0m", "\033[1m", "\033[2m", "\033[31m", "\033[32m"
    if not color:
        reset = bold = dim = red = green = ""

    lines = [
        f"{bold}deprecation inventory · MCP {SPEC_REVISION}{reset}",
        f"target: {inventory.endpoint}",
        f"as of:  {inventory.as_of.isoformat()}",
        "",
    ]

    in_use = inventory.in_use
    if in_use:
        lines.append(f"{bold}{red}{len(in_use)} deprecated feature(s) in use{reset}")
        lines.append("")
        for d in in_use:
            f = d.feature
            months = inventory.months_remaining(d)
            resolved = resolve_removal(f)
            # "on or after", always. The window is a minimum, not a schedule:
            # a date presented as a deadline gets planned around as the moment
            # the feature stops working, which is not what was promised.
            #
            # And when the registry gives a condition rather than a date, the
            # condition is what gets printed. A number invented here is a number
            # that ends up in a migration plan as a deadline.
            if isinstance(resolved, FixedRevision):
                stamp = resolved.on_or_after.isoformat()
                window = (
                    f"removable on or after {stamp} ({months} month(s) from now)"
                    if months is None or months >= 0
                    else f"removable on or after {stamp}"
                    f" — that window passed {abs(months)} month(s) ago"
                )
            else:
                window = f"removable {resolved.describe()} (not yet scheduled)"
            lines.append(f"  {red}IN USE{reset}  {bold}{f.name}{reset}"
                         + (f"  {dim}({f.sep}){reset}" if f.sep else ""))
            lines.append(f"          deprecated:  {f.deprecated_on.isoformat()}")
            lines.append(f"          {window}")
            lines.append(f"          replace with: {f.replacement}")
            lines.append(f"          {dim}{f.note}{reset}")
            lines.append(f"          {dim}evidence: {d.evidence}{reset}")
            lines.append(f"          {dim}spec: {f.citation}{reset}")
            lines.append("")
    else:
        lines.append(f"{green}no deprecated features detected{reset}")
        lines.append("")

    clear = [d for d in inventory.detections if not d.in_use]
    if clear:
        lines.append(f"{dim}{len(clear)} not detected:{reset}")
        for d in clear:
            marker = "" if d.confidence is Confidence.OBSERVED else f" [{d.confidence.value}]"
            lines.append(f"{dim}  ok      {d.feature.name}{marker}{reset}")
        lines.append("")

    unknown = [d for d in inventory.detections if d.confidence is Confidence.UNKNOWN]
    if unknown:
        lines.append(
            f"{dim}{len(unknown)} feature(s) could not be probed from the wire and are "
            f"reported as not-detected rather than absent.{reset}"
        )

    return "\n".join(lines) + "\n"


def _removal_json(inventory: Inventory, detection: Detection) -> dict[str, object]:
    """The removal window, in a shape that cannot be mistaken for a deadline.

    `monthsRemaining` is null for an event-relative window rather than absent,
    so a consumer that reads the key gets an explicit "not known" instead of a
    KeyError it might paper over with a zero.
    """
    window = resolve_removal(detection.feature)
    if isinstance(window, FixedRevision):
        return {
            "kind": "fixed_revision",
            # The key name carries the semantics too, so a consumer that never
            # reads the docs still cannot mistake it for a deadline.
            "onOrAfter": window.on_or_after.isoformat(),
            "monthsRemaining": inventory.months_remaining(detection),
        }
    return {
        "kind": "after_event",
        "condition": window.describe(),
        "sep": window.sep,
        "monthsRemaining": None,
    }


def render_json(inventory: Inventory) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "tool": "sentinel",
        "specRevision": SPEC_REVISION,
        "endpoint": inventory.endpoint,
        "asOf": inventory.as_of.isoformat(),
        "minimumNoticeMonths": MINIMUM_NOTICE_MONTHS,
        "features": [
            {
                "id": d.feature.id,
                "name": d.feature.name,
                "inUse": d.in_use,
                "confidence": d.confidence.value,
                "evidence": d.evidence,
                "deprecatedOn": d.feature.deprecated_on.isoformat(),
                "removal": _removal_json(inventory, d),
                "replacement": d.feature.replacement,
                "sep": d.feature.sep,
                "citation": d.feature.citation,
                "note": d.feature.note,
            }
            for d in inventory.detections
        ],
    }
