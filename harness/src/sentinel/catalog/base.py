"""The conformance rule model.

`docs/HANDOFF.md` §8.8. The load-bearing idea here is `INDETERMINATE`:

    "Several MUSTs — 'MUST NOT accept a token not issued for this server',
    'MUST NOT treat handle possession as authentication' — cannot be proven
    black-box against an arbitrary server. A harness that silently scores them
    as passes is lying."

So the type system makes that hard to do by accident. A rule declares its
verifiability, and `UNVERIFIABLE` rules are checked at registration time to
ensure they cannot return PASS — see `validate_registry`.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from sentinel import SPEC_REVISION
from sentinel.probe.client import Probe


class Severity(StrEnum):
    MUST = "must"
    SHOULD = "should"
    MAY = "may"


class Verifiability(StrEnum):
    #: Provable from the wire alone, against any server.
    BLACK_BOX = "black_box"
    #: Needs cooperative configuration — a known tool, a second principal, a
    #: token the harness can mint. Reported, but the scan says what it assumed.
    GRAY_BOX = "gray_box"
    #: Cannot be proven externally at all. These return INDETERMINATE, always,
    #: and are listed in the README under "limitations".
    UNVERIFIABLE = "unverifiable"


class Outcome(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    #: The rule does not apply — the server does not implement the optional
    #: feature the rule constrains. Distinct from PASS: nothing was checked.
    NOT_APPLICABLE = "not_applicable"
    #: Verifiability prevented a verdict. Never fails a gate, always printed.
    INDETERMINATE = "indeterminate"


@dataclass(slots=True)
class RuleResult:
    outcome: Outcome
    #: What was observed, in the words of someone who has to act on it.
    detail: str = ""
    #: The request/response that decided it, for a report a reader can check.
    evidence: str = ""

    @classmethod
    def passed(cls, detail: str = "", evidence: str = "") -> RuleResult:
        return cls(Outcome.PASS, detail, evidence)

    @classmethod
    def failed(cls, detail: str, evidence: str = "") -> RuleResult:
        return cls(Outcome.FAIL, detail, evidence)

    @classmethod
    def not_applicable(cls, detail: str) -> RuleResult:
        return cls(Outcome.NOT_APPLICABLE, detail)

    @classmethod
    def indeterminate(cls, detail: str) -> RuleResult:
        return cls(Outcome.INDETERMINATE, detail)


@runtime_checkable
class Rule(Protocol):
    id: str
    severity: Severity
    citation: str
    verifiability: Verifiability
    remediation: str
    fixtures: list[str]

    def evaluate(self, probe: Probe) -> RuleResult: ...


#: `MCP/<revision>/<SEVERITY>/<slug>`.
#:
#: Rule IDs are PERMANENT (§8.8). Once published, an id never changes meaning:
#: deprecate and add rather than redefine, or every historical report becomes
#: uninterpretable.
RULE_ID_PATTERN = re.compile(r"^MCP/\d{4}-\d{2}-\d{2}/(MUST|SHOULD|MAY)/[a-z0-9][a-z0-9-]*$")

SPEC_BASE = f"https://modelcontextprotocol.io/specification/{SPEC_REVISION}"

#: Fixture profiles a rule may be exercised against.
FIXTURE_NONCONFORMANT = "nonconformant"
FIXTURE_CONFORMANT = "conformant"


@dataclass(slots=True)
class BaseRule:
    """A rule built from a function.

    Using a dataclass rather than a class hierarchy keeps each rule's
    declaration and its check adjacent in one file, which is how they are read.
    """

    id: str
    severity: Severity
    citation: str
    verifiability: Verifiability
    #: What to CHANGE, not what is wrong. §8.8 calls for remediation; a report
    #: that only restates the failure leaves the reader where they started.
    remediation: str
    check: Callable[[Probe], RuleResult]
    fixtures: list[str] = field(default_factory=list)
    #: One line, shown next to the id in the text report.
    title: str = ""

    def evaluate(self, probe: Probe) -> RuleResult:
        if self.verifiability is Verifiability.UNVERIFIABLE:
            # Enforced here rather than trusted to each rule. This is the
            # property §8.8 says a dishonest harness quietly breaks, so it is
            # not left to the discipline of whoever writes the next rule.
            result = self.check(probe)
            if result.outcome is not Outcome.INDETERMINATE:
                return RuleResult.indeterminate(
                    f"{self.id} is marked UNVERIFIABLE but returned {result.outcome}; "
                    "coerced to INDETERMINATE. An unverifiable MUST scored as a pass is "
                    "the fastest way to lose a reviewer's trust."
                )
            return result
        return self.check(probe)


class Registry:
    """The rule catalog."""

    def __init__(self) -> None:
        self._rules: dict[str, BaseRule] = {}

    def register(self, rule: BaseRule) -> BaseRule:
        if rule.id in self._rules:
            raise ValueError(f"rule id {rule.id!r} is registered twice")
        self._rules[rule.id] = rule
        return rule

    def all(self) -> list[BaseRule]:
        # Sorted by id so a report's order is stable across runs and two reports
        # can be diffed.
        return sorted(self._rules.values(), key=lambda r: r.id)

    def by_severity(self, severity: Severity) -> list[BaseRule]:
        return [r for r in self.all() if r.severity is severity]

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self) -> Iterator[BaseRule]:
        return iter(self.all())


#: The single catalog. Rule modules register into it on import.
REGISTRY = Registry()


def rule(
    *,
    id: str,
    title: str,
    severity: Severity,
    citation: str,
    verifiability: Verifiability,
    remediation: str,
    fixtures: list[str] | None = None,
) -> Callable[[Callable[[Probe], RuleResult]], BaseRule]:
    """Declare and register a rule."""

    def decorate(check: Callable[[Probe], RuleResult]) -> BaseRule:
        return REGISTRY.register(
            BaseRule(
                id=id,
                title=title,
                severity=severity,
                citation=citation,
                verifiability=verifiability,
                remediation=remediation,
                check=check,
                fixtures=fixtures or [FIXTURE_NONCONFORMANT, FIXTURE_CONFORMANT],
            )
        )

    return decorate


@dataclass(slots=True)
class ValidationProblem:
    rule_id: str
    problem: str


def validate_registry(registry: Registry | None = None) -> list[ValidationProblem]:
    """Check every rule's declaration.

    `sentinel catalog validate` runs this. §9 (WP-9 pitfalls): "Writing a rule
    without a citation" is called out specifically, because a conformance claim
    with nothing to check it against is an opinion.
    """
    reg = registry if registry is not None else REGISTRY
    problems: list[ValidationProblem] = []

    for r in reg.all():
        if not RULE_ID_PATTERN.match(r.id):
            problems.append(ValidationProblem(r.id, f"id does not match {RULE_ID_PATTERN.pattern}"))
        if f"/{r.severity.upper()}/" not in r.id:
            problems.append(
                ValidationProblem(r.id, f"id does not carry its severity ({r.severity})")
            )
        if not r.citation:
            problems.append(ValidationProblem(r.id, "has no spec citation"))
        elif not r.citation.startswith(SPEC_BASE):
            problems.append(
                ValidationProblem(r.id, f"citation does not point into {SPEC_BASE}: {r.citation}")
            )
        if not r.remediation:
            problems.append(ValidationProblem(r.id, "has no remediation"))
        elif len(r.remediation) < 20:
            problems.append(
                ValidationProblem(r.id, "remediation is too short to say what to change")
            )
        if not r.title:
            problems.append(ValidationProblem(r.id, "has no title"))
        if not r.fixtures:
            problems.append(ValidationProblem(r.id, "names no fixture profile"))

    return problems
