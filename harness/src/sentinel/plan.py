"""What the 2026-07-28 revision breaks, and how much of it is your problem.

The 2026-07-28 revision is a rewrite rather than a point release. A team
running a server built against 2025-11-25 has an unscoped migration in front of
them, and the two ways to size it today are reading the changelog by hand or
buying a consulting engagement. This module sizes it from the wire.

WHAT THIS IS NOT
----------------
It is not a gate, and `sentinel migrate` always exits 0 unless the harness
itself broke. A migration report describes work, and work is not a verdict --
the same reasoning `deprecations` states for itself. A team should be able to
run this on a server they already know is non-conformant without CI going red
twice for the same reason.

THE RANKING IS DECLARED, NOT EDITORIAL
--------------------------------------
"Ranked by severity" is where a report like this normally starts lying: an
ordering nobody can reproduce is an opinion wearing a number's clothes. The
order here is a total sort over `(blocking, confidence, effort_hours, id)`,
every term of which is a stored field, and `test_the_order_is_total_and_stable`
asserts it. If the ranking is wrong you can point at the field that made it so.

CONFIDENCE IS PART OF THE ANSWER
--------------------------------
Three of the nine changes cannot be settled black-box: sessions being removed,
tasks moving to an extension, and SSE resumability. A report that listed nine
changes and quietly reported those three as "clear" would be an INDETERMINATE
scored as a PASS in a new costume, which is the single failure mode this
project's rule engine exists to prevent. They are carried with
`Confidence.UNKNOWN` and rendered in their own section, so the reader can see
the difference between "checked and fine" and "not checkable from here".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from sentinel.catalog.base import REGISTRY, Outcome
from sentinel.catalog.deprecations import Confidence
from sentinel.grade import ScanReport

__all__ = [
    "BREAKING_CHANGES",
    "BreakingChange",
    "ChangeFinding",
    "Impact",
    "MigrationPlan",
    "build_plan",
    "render_json",
    "render_text",
]


class Impact(StrEnum):
    """Whether a change stops a client working, or only degrades it."""

    #: Every client on the new revision fails against a server that has not
    #: made this change.
    BLOCKING = "blocking"
    #: The server keeps answering, but is out of spec or loses a guarantee.
    DEGRADING = "degrading"


@dataclass(frozen=True, slots=True)
class BreakingChange:
    """One change in the 2026-07-28 revision, joined to the rules that see it.

    A parallel registry keyed independently of the rule catalog, joined by id.
    Modelled on `deprecations.FEATURES` for the same reason: the rule catalog's
    lifecycle fields answer "when did sentinel ship this check", and a change's
    lifecycle answers "when did the specification move". Two clocks in adjacent
    fields on one dataclass is how a reader starts confusing them.
    """

    id: str
    title: str
    #: What a team actually has to do, in the words of someone doing it.
    what_changed: str
    remediation: str
    impact: Impact
    #: Hours for one engineer who knows the codebase. Taken from the per-change
    #: estimates in docs/MIGRATION.md rather than invented here.
    effort_hours: int
    #: Rule ids that observe this change. Empty means it is not black-box
    #: detectable, which is a fact about the wire, not an omission.
    detected_by: tuple[str, ...] = ()
    #: Section anchor in docs/MIGRATION.md, so the report can point at prose.
    doc_section: str = ""


#: The nine breaking changes, plus the two required-field additions that travel
#: with them. Effort figures come from docs/MIGRATION.md.
BREAKING_CHANGES: tuple[BreakingChange, ...] = (
    BreakingChange(
        id="handshake-removed",
        title="the initialize handshake is gone",
        what_changed=(
            "initialize and notifications/initialized were removed. The protocol "
            "version and client capabilities now ride in _meta on every request, so "
            "there is no negotiation turn to hang state on."
        ),
        remediation=(
            "Delete the handshake methods and read protocol version and capabilities "
            "from _meta on each request instead."
        ),
        impact=Impact.BLOCKING,
        effort_hours=16,
        detected_by=("MCP/2026-07-28/MUST/initialize-removed",),
        doc_section="removed-outright",
    ),
    BreakingChange(
        id="discover-required",
        title="server/discover is a new MUST",
        what_changed=(
            "Every server must implement server/discover, and must answer it without "
            "a negotiated protocol version, because there is no longer a negotiation."
        ),
        remediation=("Implement server/discover and answer it before any version is agreed."),
        impact=Impact.BLOCKING,
        effort_hours=8,
        detected_by=(
            "MCP/2026-07-28/MUST/discover-implemented",
            "MCP/2026-07-28/MUST/discover-without-negotiated-version",
        ),
        doc_section="removed-outright",
    ),
    BreakingChange(
        id="methods-removed",
        title="ping, logging/setLevel and the roots methods were removed",
        what_changed=(
            "ping, logging/setLevel, resources/subscribe, resources/unsubscribe and "
            "the roots methods are gone. A server still answering them is answering "
            "methods the revision does not define."
        ),
        remediation=(
            "Remove the handlers, and answer the removed method names with "
            "method-not-found so a stale client fails loudly rather than silently."
        ),
        impact=Impact.BLOCKING,
        effort_hours=8,
        detected_by=(
            "MCP/2026-07-28/MUST/ping-removed",
            "MCP/2026-07-28/MUST/logging-set-level-removed",
            "MCP/2026-07-28/MUST/resources-subscribe-removed",
            "MCP/2026-07-28/MUST/resources-unsubscribe-removed",
            "MCP/2026-07-28/MUST/roots-list-removed",
        ),
        doc_section="removed-outright",
    ),
    BreakingChange(
        id="mrtr-replaces-server-initiated",
        title="the server stops calling the client (MRTR)",
        what_changed=(
            "Server-initiated requests -- roots/list, sampling/createMessage, "
            "elicitation/create -- are replaced by the MRTR pattern, where the server "
            "returns a request for the client to satisfy and the client retries."
        ),
        remediation=(
            "Replace server-initiated calls with an MRTR flow, and make the retry "
            "idempotent: a duplicate must replay the recorded result with no further "
            "effects."
        ),
        impact=Impact.BLOCKING,
        effort_hours=24,
        detected_by=("MCP/2026-07-28/MUST/sampling-create-message-removed",),
        doc_section="mrtr-the-server-stops-calling-the-client",
    ),
    BreakingChange(
        id="cacheable-result-required",
        title="ttlMs and cacheScope became required on list results",
        what_changed=(
            "Every cacheable result must carry ttlMs and cacheScope. A list result "
            "without them is not answerable by a conformant client cache."
        ),
        remediation="Add ttlMs and cacheScope to every list result.",
        impact=Impact.BLOCKING,
        effort_hours=4,
        detected_by=(
            "MCP/2026-07-28/MUST/cacheable-results-carry-ttl",
            "MCP/2026-07-28/MUST/cacheable-results-carry-scope",
        ),
        doc_section="cacheableresult-became-required",
    ),
    BreakingChange(
        id="header-contract",
        title="Mcp-Method and Mcp-Name are required headers",
        what_changed=(
            "Requests carry Mcp-Method and Mcp-Name headers so a proxy can route and "
            "authorize without parsing the body, and a body that disagrees with the "
            "headers must be rejected."
        ),
        remediation=(
            "Require both headers, and reject a disagreeing body with -32020 rather "
            "than trusting either side."
        ),
        impact=Impact.BLOCKING,
        effort_hours=8,
        detected_by=(
            "MCP/2026-07-28/MUST/mcp-method-header-required",
            "MCP/2026-07-28/MUST/mcp-name-header-required",
            "MCP/2026-07-28/MUST/header-body-mismatch-rejected",
        ),
        doc_section="the-header-contract",
    ),
    BreakingChange(
        id="error-codes-renumbered",
        title="error codes were renumbered",
        what_changed=(
            "The -32020..-32099 band is reserved by the specification and the legacy "
            "sub-range below it is retired. A server still allocating in either is "
            "colliding with codes the revision defines."
        ),
        remediation=(
            "Move server-allocated codes out of the reserved and legacy ranges, and "
            "return invalid-params for a resource that does not exist."
        ),
        impact=Impact.DEGRADING,
        effort_hours=4,
        detected_by=(
            "MCP/2026-07-28/MUST/no-errors-in-reserved-range",
            "MCP/2026-07-28/MUST/resource-not-found-is-invalid-params",
            "MCP/2026-07-28/SHOULD/no-errors-in-legacy-range",
        ),
        doc_section="error-codes-moved",
    ),
    BreakingChange(
        id="sessions-removed",
        title="sessions were removed; state becomes server-minted handles",
        what_changed=(
            "Mcp-Session-Id is gone and list endpoints no longer vary per connection. "
            "Cross-call state is carried as handles the server mints and re-verifies "
            "on every resolution."
        ),
        remediation=(
            "Remove session affinity, make list results connection-independent, and "
            "re-verify every handle on use rather than trusting possession of it."
        ),
        impact=Impact.BLOCKING,
        effort_hours=24,
        # Only one observable consequence is checkable black-box; the removal
        # of session state itself is not.
        detected_by=("MCP/2026-07-28/MUST/tools-list-connection-independent",),
        doc_section="state-sessions-become-handles",
    ),
    BreakingChange(
        id="tasks-moved-to-extension",
        title="tasks moved out of core into an official extension",
        what_changed=(
            "Task methods are no longer part of the core protocol. A server that "
            "implements them is implementing an extension, and must say so."
        ),
        remediation=(
            "Declare the tasks extension explicitly rather than assuming core "
            "support, or drop the methods."
        ),
        impact=Impact.DEGRADING,
        effort_hours=8,
        detected_by=(),
        doc_section="the-shape-of-the-change",
    ),
    BreakingChange(
        id="sse-resumability-removed",
        title="SSE resumability and Last-Event-ID were removed",
        what_changed=(
            "The revision drops SSE resumability. A server relying on Last-Event-ID "
            "to resume a stream is relying on a mechanism the revision deleted."
        ),
        remediation=(
            "Remove resumption logic and make the transport request-scoped, which is "
            "what the removal of sessions makes possible."
        ),
        impact=Impact.DEGRADING,
        effort_hours=8,
        detected_by=(),
        doc_section="the-shape-of-the-change",
    ),
)

CHANGES_BY_ID = {c.id: c for c in BREAKING_CHANGES}


@dataclass(slots=True)
class ChangeFinding:
    """One change, and what the scan was able to say about it."""

    change: BreakingChange
    confidence: Confidence
    #: Rule ids that FAILed, i.e. work this server still has to do.
    failing_rules: tuple[str, ...] = ()
    #: Rule ids that PASSed, i.e. work already done.
    passing_rules: tuple[str, ...] = ()
    #: Rule ids the harness could not settle.
    indeterminate_rules: tuple[str, ...] = ()

    @property
    def outstanding(self) -> bool:
        """True when the scan saw work still to do."""
        return bool(self.failing_rules)

    @property
    def sort_key(self) -> tuple[int, int, int, str]:
        """The declared ranking. Every term is a stored field.

        Blocking before degrading; observed before unknown, because a change
        you can see is a change you can plan; then the larger job first, since
        that is what sets the schedule; then the id, so the order is total.
        """
        return (
            0 if self.change.impact is Impact.BLOCKING else 1,
            {Confidence.OBSERVED: 0, Confidence.ADVERTISED: 1, Confidence.UNKNOWN: 2}[
                self.confidence
            ],
            -self.change.effort_hours,
            self.change.id,
        )


@dataclass(slots=True)
class MigrationPlan:
    endpoint: str
    findings: list[ChangeFinding] = field(default_factory=list)

    @property
    def outstanding(self) -> list[ChangeFinding]:
        return [f for f in self.findings if f.outstanding]

    @property
    def undetectable(self) -> list[ChangeFinding]:
        return [f for f in self.findings if f.confidence is Confidence.UNKNOWN]

    @property
    def clear(self) -> list[ChangeFinding]:
        return [
            f for f in self.findings if not f.outstanding and f.confidence is not Confidence.UNKNOWN
        ]

    @property
    def outstanding_hours(self) -> int:
        """Effort for what the scan actually saw. Excludes the undetectable.

        Summing the unknown ones in would produce a total that looks like an
        estimate and is partly a guess about work that may not exist.
        """
        return sum(f.change.effort_hours for f in self.outstanding)


def build_plan(report: ScanReport, *, endpoint: str | None = None) -> MigrationPlan:
    """Join a finished scan onto the breaking-change registry.

    Takes a ScanReport rather than a Probe: the scan already asked every
    question this needs answered, and asking twice would double the traffic to
    someone else's server for no new information.
    """
    by_rule = {f.rule.id: f.outcome for f in report.findings}
    known_rules = {r.id for r in REGISTRY.all(include_deprecated=True)}

    plan = MigrationPlan(endpoint=endpoint or report.endpoint)
    for change in BREAKING_CHANGES:
        failing, passing, indeterminate = [], [], []
        for rule_id in change.detected_by:
            if rule_id not in known_rules:
                # A change naming a rule that does not exist is a defect in this
                # table, and saying so beats silently reporting the change clear.
                indeterminate.append(rule_id)
                continue
            outcome = by_rule.get(rule_id)
            if outcome is Outcome.FAIL:
                failing.append(rule_id)
            elif outcome is Outcome.PASS:
                passing.append(rule_id)
            else:
                indeterminate.append(rule_id)

        if not change.detected_by:
            confidence = Confidence.UNKNOWN
        elif failing or passing:
            confidence = Confidence.OBSERVED
        else:
            confidence = Confidence.UNKNOWN

        plan.findings.append(
            ChangeFinding(
                change=change,
                confidence=confidence,
                failing_rules=tuple(failing),
                passing_rules=tuple(passing),
                indeterminate_rules=tuple(indeterminate),
            )
        )

    plan.findings.sort(key=lambda f: f.sort_key)
    return plan


def render_text(plan: MigrationPlan) -> str:
    """The report a person reads before scoping the work."""
    out: list[str] = []
    out.append(f"migration readiness: {plan.endpoint}")
    out.append(f"target revision:     2026-07-28 ({len(BREAKING_CHANGES)} breaking changes)")
    out.append("")

    if plan.outstanding:
        out.append(
            f"OUTSTANDING ({len(plan.outstanding)}), about {plan.outstanding_hours} engineer-hours"
        )
        for f in plan.outstanding:
            out.append(f"  [{f.change.impact.value}] {f.change.title}")
            out.append(f"      {f.change.what_changed}")
            out.append(f"      do: {f.change.remediation}")
            seen = ", ".join(
                r.rsplit("/", 2)[-2] + "/" + r.rsplit("/", 1)[-1] for r in f.failing_rules
            )
            out.append(f"      ~{f.change.effort_hours}h, seen by: {seen}")
        out.append("")

    if plan.clear:
        out.append(f"ALREADY DONE ({len(plan.clear)})")
        for f in plan.clear:
            out.append(f"  {f.change.title}")
        out.append("")

    if plan.undetectable:
        out.append(f"NOT CHECKABLE FROM HERE ({len(plan.undetectable)})")
        out.append("  These are reported as unknown rather than clear. A scan cannot settle")
        out.append("  them from the wire, and a report that called them done would be scoring")
        out.append("  an indeterminate as a pass.")
        for f in plan.undetectable:
            out.append(
                f"  [{f.change.impact.value}] {f.change.title} "
                f"(~{f.change.effort_hours}h if it applies)"
            )
            out.append(f"      check by hand: {f.change.remediation}")
        out.append("")

    out.append(
        "This is a description of work, not a verdict: `sentinel migrate` never fails a gate."
    )
    return "\n".join(out)


def render_json(plan: MigrationPlan) -> dict[str, object]:
    return {
        "endpoint": plan.endpoint,
        "target_revision": "2026-07-28",
        "breaking_changes": len(BREAKING_CHANGES),
        "outstanding_count": len(plan.outstanding),
        "outstanding_effort_hours": plan.outstanding_hours,
        "undetectable_count": len(plan.undetectable),
        "changes": [
            {
                "id": f.change.id,
                "title": f.change.title,
                "impact": f.change.impact.value,
                "confidence": f.confidence.value,
                "effort_hours": f.change.effort_hours,
                "outstanding": f.outstanding,
                "remediation": f.change.remediation,
                "failing_rules": list(f.failing_rules),
                "passing_rules": list(f.passing_rules),
                "indeterminate_rules": list(f.indeterminate_rules),
                "doc_section": f.change.doc_section,
            }
            for f in plan.findings
        ],
    }
