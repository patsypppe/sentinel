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
from dataclasses import dataclass, field

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
from sentinel.probe.client import Probe
from sentinel.probe.transport import DEFAULT_RETRIES

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

    @property
    def outcome(self) -> Outcome:
        return self.result.outcome


@dataclass(slots=True)
class ScanReport:
    endpoint: str
    spec_revision: str
    findings: list[Finding] = field(default_factory=list)
    started_at: float = 0.0
    elapsed_s: float = 0.0

    def by_outcome(self, outcome: Outcome, severity: Severity | None = None) -> list[Finding]:
        return [
            f
            for f in self.findings
            if f.outcome is outcome and (severity is None or f.rule.severity is severity)
        ]

    @property
    def must_failures(self) -> list[Finding]:
        return self.by_outcome(Outcome.FAIL, Severity.MUST)

    @property
    def indeterminate(self) -> list[Finding]:
        return self.by_outcome(Outcome.INDETERMINATE)

    def counts(self, severity: Severity | None = None) -> dict[str, int]:
        return {
            outcome.value: len(self.by_outcome(outcome, severity)) for outcome in Outcome
        }

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
) -> ScanReport:
    """Evaluate every rule against one endpoint."""
    reg = registry if registry is not None else REGISTRY
    report = ScanReport(endpoint=endpoint, spec_revision=SPEC_REVISION, started_at=time.time())

    rules = reg.all(include_deprecated=include_deprecated)
    if only is not None:
        rules = [r for r in rules if r.id in only]

    started = time.perf_counter()
    with Probe(
        endpoint,
        timeout=timeout,
        bearer_token=bearer_token,
        verify=verify,
        proxy=proxy,
        client_cert=client_cert,
        retries=retries,
        budgets=budgets,
    ) as probe:
        for r in rules:
            rule_started = time.perf_counter()
            try:
                result = r.evaluate(probe)
            except Exception as exc:
                # A rule that raises is a HARNESS defect, and saying so is more
                # useful than reporting it as a failure of the target. It lands
                # in the INDETERMINATE bucket, where it does not fail a gate and
                # is impossible to overlook.
                result = RuleResult.indeterminate(
                    f"the rule raised {type(exc).__name__}: {exc}. This is a defect in the "
                    "harness, not a finding about the server."
                )
            report.findings.append(
                Finding(rule=r, result=result, elapsed_s=time.perf_counter() - rule_started)
            )

    report.elapsed_s = time.perf_counter() - started
    return report


def unverifiable_rules(registry: Registry | None = None) -> list[BaseRule]:
    """Every rule that cannot be settled black-box.

    The README lists these under "limitations". §8.8: "Saying so is the
    credibility move; papering over it is the thing a reviewer will catch."
    """
    reg = registry if registry is not None else REGISTRY
    return [r for r in reg.all() if r.verifiability is Verifiability.UNVERIFIABLE]
