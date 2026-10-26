"""Scan execution and the exit-code contract.

`docs/HANDOFF.md` §8.8:

    "`sentinel scan --gate must` exits 1 if any MUST rule returns FAIL, and 0
    otherwise. INDETERMINATE never fails a gate but is always printed. Every
    other subcommand reserves non-zero for harness errors — CI must distinguish
    'the server is wrong' from 'the scanner broke'."

That last sentence is why the exit codes are defined here as constants rather
than returned as bare integers from wherever they are decided.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sentinel import SPEC_REVISION
from sentinel.budget import BudgetPolicy
from sentinel.catalog.base import (
    REGISTRY,
    BaseRule,
    Namespace,
    Outcome,
    Registry,
    RuleResult,
    Severity,
    Verifiability,
)
from sentinel.fingerprint import fingerprint, target_identity
from sentinel.probe.client import SAFE_MODE_REFUSAL, Probe
from sentinel.probe.transport import DEFAULT_RETRIES

if TYPE_CHECKING:
    from sentinel.waivers import Waiver

#: The scan passed its gate.
EXIT_OK = 0
#: The TARGET failed the gate. A product verdict, not a tool error.
EXIT_GATE_FAILED = 1
#: The SCANNER could not complete. Reserved so CI can tell the two apart: a
#: scanner that reports "the server is wrong" when it actually crashed is worse
#: than one that reports nothing.
EXIT_HARNESS_ERROR = 2


#: Beyond-spec categories a gate may select, lower-cased as the CLI accepts
#: them. Derived from RULE_ID_PATTERN so the two cannot drift apart.
BEYOND_SPEC_CATEGORIES = ("security", "style", "ops")

#: How a rule left unsettled by safe mode is labelled in every report.
SAFE_MODE_DETAIL = "skipped in safe mode"


@dataclass(frozen=True, slots=True)
class Gate:
    """What a `--gate` selects: one namespace, and within it one bucket.

    Kept as a type rather than a pair of loose arguments because the invariant
    that matters is that the two fields are chosen together. A gate that
    considered MCP rules with a SENTINEL category, or a beyond-spec category
    with severity MUST, would be a verdict about nothing.
    """

    namespace: Namespace
    severity: Severity
    #: "" for a spec gate; "OPS" / "SECURITY" / "STYLE" for a beyond-spec one.
    category: str = ""

    @classmethod
    def spec(cls, severity: Severity) -> Gate:
        return cls(namespace=Namespace.MCP, severity=severity, category="")

    @classmethod
    def beyond(cls, category: str) -> Gate:
        """A gate over one beyond-spec category.

        Beyond-spec rules are declared at MUST severity so that a FAIL is a
        FAIL; the category, not the severity, is what makes them opt-in.
        """
        return cls(
            namespace=Namespace.SENTINEL,
            severity=Severity.MUST,
            category=category.upper(),
        )

    def __str__(self) -> str:
        return self.category.lower() if self.category else self.severity.value


@dataclass(slots=True)
class Finding:
    rule: BaseRule
    result: RuleResult
    elapsed_s: float
    #: Stable identity of this finding on this target; see `sentinel.fingerprint`.
    fingerprint: str = ""
    #: The unexpired waiver covering a FAIL, if any. Waived findings stay in the
    #: report and never count toward the gate.
    waived_by: Waiver | None = None
    #: A waiver that matched but has expired. The finding re-fails, labelled.
    waiver_expired: Waiver | None = None
    #: Present in the baseline: known, accepted, not gating.
    baselined: bool = False
    #: True when this rule did not exist at baseline time, so a failure is new by
    #: construction and the report says why.
    rule_is_new: bool = False

    @property
    def outcome(self) -> Outcome:
        return self.result.outcome

    @property
    def suppressed(self) -> bool:
        """A FAIL that is accounted for and therefore does not gate."""
        return self.outcome is Outcome.FAIL and (self.waived_by is not None or self.baselined)

    @property
    def verified_by(self) -> str:
        """`black_box`, or the gray-box evidence kind that settled the verdict."""
        return self.result.verified_by or "black_box"


@dataclass(slots=True)
class ScanReport:
    endpoint: str
    spec_revision: str
    findings: list[Finding] = field(default_factory=list)
    started_at: float = 0.0
    elapsed_s: float = 0.0
    #: True when the scan ran in safe mode (see `Probe.safe`). A report has to
    #: say so: a rule left INDETERMINATE because the scanner chose not to call a
    #: tool is a different statement from one the server prevented.
    safe: bool = False
    #: The configured fleet-target name, when this scan is one target of several.
    target_name: str | None = None
    #: Fingerprints in the baseline that no longer fail (set by the baseline).
    fixed: list[str] = field(default_factory=list)
    #: The resolved policy as a report block (see `Policy.describe`).
    policy: dict[str, object] = field(default_factory=dict)
    #: Waivers that matched nothing, or are expiring: housekeeping a reader needs.
    waiver_notes: list[str] = field(default_factory=list)
    #: Canonical SHA-256 of the target's tool manifest at scan time.
    manifest_hash: str | None = None
    #: Which protocol generation answered: "current", "legacy", "auth", "other" or
    #: "unreachable" (see `population.classify`), and a human sentence about it.
    generation: str = ""
    generation_detail: str = ""

    @property
    def target(self) -> str:
        return target_identity(self.endpoint, self.target_name)

    @property
    def skipped_for_safety(self) -> list[Finding]:
        return [
            f
            for f in self.findings
            if f.outcome is Outcome.INDETERMINATE and SAFE_MODE_DETAIL in f.result.detail
        ]

    def by_outcome(self, outcome: Outcome, severity: Severity | None = None) -> list[Finding]:
        return [
            f
            for f in self.findings
            if f.outcome is outcome and (severity is None or f.rule.severity is severity)
        ]

    def by_outcome_fail(self) -> list[Finding]:
        return self.by_outcome(Outcome.FAIL)

    @property
    def must_failures(self) -> list[Finding]:
        return self.by_outcome(Outcome.FAIL, Severity.MUST)

    @property
    def indeterminate(self) -> list[Finding]:
        return self.by_outcome(Outcome.INDETERMINATE)

    def counts(self, severity: Severity | None = None) -> dict[str, int]:
        return {outcome.value: len(self.by_outcome(outcome, severity)) for outcome in Outcome}

    def gate(self, gate: Gate | Severity | None) -> int:
        """The exit code for `gate`.

        INDETERMINATE never fails it. That is not leniency — it is the whole
        point of having the bucket: a rule the harness cannot settle must not be
        reported as a verdict in either direction.

        A gate selects exactly one namespace, and that separation is the
        contract, not an implementation detail:

        * A SPEC gate (`--gate must`) considers MCP rules only. A SENTINEL rule
          is an opinion this project holds and the specification does not;
          letting one fail `--gate must` would make a conformance verdict
          unfalsifiable.
        * A BEYOND-SPEC gate (`--gate ops`) considers one SENTINEL category
          only. It cannot fail on a spec rule either, so a red build names which
          kind of claim it is making. A team that wants both runs both.

        A bare `Severity` is still accepted and still means exactly what it
        meant before, so every existing caller and every existing CI invocation
        keeps its behaviour byte for byte.
        """
        if gate is None:
            return EXIT_OK
        if isinstance(gate, Severity):
            gate = Gate.spec(gate)
        failed = [
            f
            for f in self.by_outcome(Outcome.FAIL, gate.severity)
            if f.rule.namespace is gate.namespace
            and (not gate.category or f.rule.category == gate.category)
            # A waived or baselined failure is accounted for. It is still in the
            # report, in its own bucket, but it does not turn the build red.
            and not f.suppressed
        ]
        return EXIT_GATE_FAILED if failed else EXIT_OK


def run_scan(
    endpoint: str,
    *,
    registry: Registry | None = None,
    timeout: float = 10.0,
    bearer_token: str | None = None,
    only: set[str] | None = None,
    include_deprecated: bool = False,
    verify: bool | str = True,
    proxy: str | None = None,
    client_cert: str | tuple[str, str] | None = None,
    retries: int = DEFAULT_RETRIES,
    budgets: BudgetPolicy | None = None,
    safe: bool = False,
    concurrency: int = 8,
    target_name: str | None = None,
    skip: frozenset[str] = frozenset(),
    probe_factory: Callable[[], Probe] | None = None,
    context: dict[str, object] | None = None,
    detect_generation: bool = True,
) -> ScanReport:
    """Evaluate every rule against one endpoint.

    Rules are independent by construction -- each builds its own requests and
    asserts on its own responses -- so they run in a thread pool, and **each rule
    gets its own `Probe`**, which is what guarantees no two rules share an HTTP
    client. A rule that deliberately disturbs the target declares `exclusive` and
    runs alone, after the pool drains.

    The report is deterministic regardless of completion order: findings are
    ordered by rule id before anyone sees them, so two scans of the same server
    produce the same report.
    """
    reg = registry if registry is not None else REGISTRY
    report = ScanReport(
        endpoint=endpoint,
        spec_revision=SPEC_REVISION,
        started_at=time.time(),
        safe=safe,
        target_name=target_name,
    )

    rules = reg.all(include_deprecated=include_deprecated)
    if only is not None:
        rules = [r for r in rules if r.id in only]
    rules = [r for r in rules if r.id not in skip]
    identity = report.target

    def make_probe(*, legacy: bool = False) -> Probe:
        if probe_factory is not None:
            return probe_factory()
        return Probe(
            endpoint,
            timeout=timeout,
            bearer_token=bearer_token,
            verify=verify,
            proxy=proxy,
            client_cert=client_cert,
            retries=retries,
            budgets=budgets,
            safe=safe,
            context=context,
            legacy=legacy,
        )

    if detect_generation:
        report.generation, report.generation_detail = _generation(make_probe)

    def run_one(r: BaseRule) -> Finding:
        rule_started = time.perf_counter()
        try:
            # A server that has not migrated cannot answer the current wire at all, so the
            # rules that only read its tool manifest speak the previous revision to it.
            # Every other rule still tests the current one, and fails honestly.
            use_legacy = report.generation == "legacy" and r.id in ERA_INDEPENDENT
            with make_probe(legacy=use_legacy) as probe:
                result = r.evaluate(probe)
        except Exception as exc:
            # A rule that raises is a HARNESS defect, and saying so is more
            # useful than reporting it as a failure of the target. It lands in
            # the INDETERMINATE bucket, where it does not fail a gate and is
            # impossible to overlook.
            result = RuleResult.indeterminate(
                f"the rule raised {type(exc).__name__}: {exc}. This is a defect in the "
                "harness, not a finding about the server."
            )
        result = _relabel_safe_mode(result)
        return Finding(
            rule=r,
            result=result,
            elapsed_s=time.perf_counter() - rule_started,
            fingerprint=fingerprint(r.id, identity, r.evidence_key, result.key),
        )

    started = time.perf_counter()
    shared = [r for r in rules if not r.exclusive]
    alone = [r for r in rules if r.exclusive]
    findings: list[Finding] = []
    if shared:
        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
            findings.extend(pool.map(run_one, shared))
    findings.extend(run_one(r) for r in alone)
    findings.sort(key=lambda f: f.rule.id)
    report.findings = findings
    report.elapsed_s = time.perf_counter() - started
    report.manifest_hash = _manifest_hash(make_probe)
    return report


#: Rules whose verdict depends only on what a server says in tools/list (or on one HTTP header),
#: not on which protocol revision carries it. Against a server that has not migrated they run
#: over a legacy session instead of reporting "unreachable".
#: What `sentinel lint` runs: ERA_INDEPENDENT minus the one rule that needs an HTTP endpoint.
ERA_INDEPENDENT = frozenset(
    {
        "MCP/2026-07-28/SHOULD/tool-names-well-formed",
        "MCP/2026-07-28/SHOULD/tool-names-unique-within-server",
        "MCP/2026-07-28/SHOULD/tools-list-is-deterministic",
        "MCP/2026-07-28/MUST/tools-declare-input-schema",
        "MCP/2026-07-28/MUST/tools-declare-valid-input-schema",
        "MCP/2026-07-28/MUST/tools-are-named",
        "MCP/2026-07-28/MUST/invalid-origin-rejected",
        "SENTINEL/STYLE/description-states-purpose",
        "SENTINEL/STYLE/parameters-are-described",
        "SENTINEL/STYLE/tools-have-descriptions",
        "SENTINEL/STYLE/tools-sorted-by-name",
        "SENTINEL/SECURITY/tool-description-injection",
        "SENTINEL/OPS/tool-descriptions-are-distinct",
    }
)


def _generation(make_probe: Callable[..., Probe]) -> tuple[str, str]:
    """Which protocol generation the target speaks. Best effort, never a finding."""
    from sentinel.population import classify

    try:
        with make_probe() as probe:
            klass, _status, detail, _framing = classify(probe)
    except Exception:
        return "", ""
    return klass, detail


def _manifest_hash(make_probe: Callable[..., Probe]) -> str | None:
    """The canonical hash of the target's tool manifest, or None if unreadable.

    Best effort and never a finding: a target whose manifest cannot be read has
    already failed the rules that say so, and a missing hash must not turn a
    finished scan into an error.
    """
    from sentinel.snapshot import canonical_hash, fetch_tools

    try:
        with make_probe() as probe:
            tools, _ = fetch_tools(probe)
    except Exception:
        return None
    if tools is None:
        return None
    return canonical_hash([tools[name] for name in sorted(tools)])


def _relabel_safe_mode(result: RuleResult) -> RuleResult:
    """Say "skipped in safe mode" where a rule said "unreachable".

    Rules report a request that never reached the server as "the server was
    unreachable: <reason>". When the reason is that safe mode declined to send
    it, "unreachable" is false and would read as an outage, so the detail is
    rewritten here, once, instead of in every rule.
    """
    if result.outcome is not Outcome.INDETERMINATE or SAFE_MODE_REFUSAL not in result.detail:
        return result
    reason = result.detail[result.detail.index(SAFE_MODE_REFUSAL) + len(SAFE_MODE_REFUSAL) :]
    return RuleResult.indeterminate(f"{SAFE_MODE_DETAIL}: did not invoke{reason}")


def unverifiable_rules(registry: Registry | None = None) -> list[BaseRule]:
    """Every rule that cannot be settled black-box.

    The README lists these under "limitations". §8.8: "Saying so is the
    credibility move; papering over it is the thing a reviewer will catch."
    """
    reg = registry if registry is not None else REGISTRY
    return [r for r in reg.all() if r.verifiability is Verifiability.UNVERIFIABLE]


#: The rules `sentinel lint` runs. They read only a server's tool manifest, so they work over
#: any transport, including a stdio child process.
LINT_RULES = ERA_INDEPENDENT - {"MCP/2026-07-28/MUST/invalid-origin-rejected"}
