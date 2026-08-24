# Sentinel v1 — Phase A & B Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct four verified spec violations in the repository, then grow the conformance catalog from 35 rules to roughly 74 — so that every rule's severity matches the specification's and the highest-traffic MCP methods are actually covered.

**Architecture:** The harness keeps its shape — a `Registry` of `BaseRule`, a deliberately literal `Probe`, a sequential `run_scan`. Phase A adds a *rule lifecycle* (`deprecated_in` / `superseded_by`) so severity corrections can deprecate-and-supersede instead of editing published rule IDs, fixes the probe's own malformed requests, models deprecation removal windows that are not simple date arithmetic, and moves the broker's error codes out of a sub-range the specification retired. Phase B then adds five new rule modules on top of that corrected base.

**Tech Stack:** Python 3.12 (`httpx`, `typer`, `pytest`, `ruff`, `mypy --strict`, `uv`), Go 1.23+ (`pgx`, `golangci-lint`), Postgres 17, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-08-23-sentinel-v1-design.md` (SN-DSN-002). Sections §3 and §6 are the ones this plan implements. Read them before starting.

## Global Constraints

Copied verbatim from `CLAUDE.md` and the spec. Every task's requirements implicitly include this section.

- **The specification wins.** Where this repository and [MCP `2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28/) disagree, the spec is right and the repository is wrong. Every rule cites a spec URL; if you cannot cite one, the rule does not belong in the `MCP/` catalog.
- **Rule IDs are permanent.** Once published, an ID never changes meaning. Deprecate and add; never redefine. This is why Task 1 exists.
- **An unverifiable MUST returns `INDETERMINATE`, never a false pass.**
- **The harness must never import broker internals** and must run against any endpoint URL.
- **The probe is deliberately literal — no MCP SDK.** An SDK that helpfully adds `Mcp-Method` makes the rule requiring `Mcp-Method` untestable.
- **Structs, never `map[string]any`** in Go for anything serialized deterministically. `json.RawMessage` for pass-through.
- **No model API key anywhere.** No LLM call in any rule, including heuristics.
- **Exit codes are a contract:** `0` passed, `1` the *target* failed the gate, `2` the *scanner* could not run. Never conflated.
- Go lives behind Homebrew here: `export PATH="/opt/homebrew/bin:$PATH"`.
- Commit format: `<type>: <description>` — `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`. **No `Co-Authored-By` trailers** — this repository's history has none.
- One branch and one PR per work package: `feat/wp-N-<slug>`.
- `make check` (golangci-lint + `go test -race` + ruff + mypy + `pytest -m unit`) must be green before every commit.

## Verification commands

```bash
export PATH="/opt/homebrew/bin:$PATH"
make check                                   # everything, offline, <2 min
uv run pytest tests/harness -m unit -q       # harness unit tests only
uv run pytest tests/harness/test_catalog.py -q
uv run sentinel catalog validate             # every rule declares what it must
uv run mypy --strict harness/src/sentinel    # via `make typecheck`
uv run ruff check harness fixtures tests scripts
cd broker && go test ./... -race             # Go unit tests
```

---

## File structure

### Phase A

| File | Responsibility |
|---|---|
| `harness/src/sentinel/catalog/base.py` (modify) | Adds `Namespace`, lifecycle fields, `Registry.all(include_deprecated=)`, lifecycle validation |
| `harness/src/sentinel/catalog/should/envelope.py` (create) | The SHOULD successors to two wrongly-graded MUSTs |
| `harness/src/sentinel/catalog/beyond/__init__.py` (create) | The `SENTINEL/` beyond-spec namespace package |
| `harness/src/sentinel/catalog/beyond/style.py` (create) | `SENTINEL/STYLE/tools-sorted-by-name`, successor to the demoted SHOULD |
| `harness/src/sentinel/catalog/must/envelope.py` (modify) | Deprecates two rules; gains `tools-list-connection-independent` |
| `harness/src/sentinel/catalog/should/ordering.py` (modify) | Deprecates `tools-sorted-by-name` |
| `harness/src/sentinel/catalog/deprecations.py` (modify) | Per-feature dates; `RemovalWindow` as three variants |
| `harness/src/sentinel/probe/client.py` (modify) | Sends `clientCapabilities`; `new_connection()`; new overrides |
| `harness/src/sentinel/grade.py` (modify) | Threads `include_deprecated`; gate ignores the `SENTINEL/` namespace |
| `harness/src/sentinel/cli.py` (modify) | `--include-deprecated-rules` |
| `harness/src/sentinel/report/text.py`, `json_report.py`, `sarif.py` (modify) | Render lifecycle and namespace |
| `broker/internal/envelope/errors.go` (modify) | Codes leave `-32000…-32019` |
| `harness/src/sentinel/catalog/should/errors.py` (create) | `SHOULD/no-errors-in-legacy-range` |
| `tests/harness/test_lifecycle.py`, `test_removal_windows.py`, `test_probe_meta.py` (create) | |

### Phase B

| File | Responsibility |
|---|---|
| `harness/src/sentinel/probe/client.py` (modify) | `prompts_get()`, `notify()`, `origin`, protocol-version-header overrides |
| `harness/src/sentinel/probe/transport.py` (modify) | `verify`, `proxy`, `client_cert`, bounded transport-only retry |
| `harness/src/sentinel/catalog/must/meta.py` (create) | Required `_meta` fields and their mandated HTTP 400s |
| `harness/src/sentinel/catalog/must/http.py` (create) | HTTP status, Content-Type, Origin, 202, 404, 405 |
| `harness/src/sentinel/catalog/must/mrtr.py` (create) | MRTR shape and forged-`requestState` rejection |
| `harness/src/sentinel/catalog/must/primitives.py` (create) | `resources/read`, `prompts/get`, capability↔method truthfulness |
| `harness/src/sentinel/catalog/must/schemas.py` (create) | The `x-mcp-header` constraint set and schema validity |
| `harness/src/sentinel/catalog/should/naming.py` (create) | Tool-name well-formedness and uniqueness |
| `fixtures/server/nonconformant.py` (modify) | A seeded violation per new black-box rule |
| `fixtures/server/conformant.py` (modify) | Each new requirement implemented correctly |
| `fixtures/server/partial.py` (create) | No resources, no prompts, no MRTR — exercises `NOT_APPLICABLE` |

---

# WP-14 — Rule lifecycle, severity corrections, deprecation fidelity, probe metadata

**Branch:** `feat/wp-14-rule-lifecycle`

Implements spec §3.2, §3.3, §3.4 and §4.1.

---

### Task 1: Rule lifecycle and the beyond-spec namespace

**Files:**
- Modify: `harness/src/sentinel/catalog/base.py`
- Test: `tests/harness/test_lifecycle.py` (create)

**Interfaces:**
- Consumes: nothing (first task)
- Produces:
  - `Namespace` — `StrEnum` with `MCP = "MCP"`, `SENTINEL = "SENTINEL"`
  - `BaseRule.introduced_in: str`, `BaseRule.deprecated_in: str | None`, `BaseRule.superseded_by: str | None`, `BaseRule.rationale: str`
  - `BaseRule.namespace -> Namespace` (property), `BaseRule.is_deprecated -> bool` (property), `BaseRule.slug -> str` (property)
  - `Registry.all(*, include_deprecated: bool = False) -> list[BaseRule]`
  - `Registry.by_severity(severity, *, include_deprecated: bool = False) -> list[BaseRule]`
  - `rule(...)` decorator gains keyword-only `introduced_in`, `deprecated_in`, `superseded_by`, `rationale`

- [ ] **Step 1: Write the failing test**

Create `tests/harness/test_lifecycle.py`:

```python
"""The rule lifecycle.

Rule IDs are permanent (HANDOFF §8.8). When a rule's severity turns out to be
wrong, the catalog deprecates it and publishes a successor rather than editing
the published ID -- otherwise every historical report becomes uninterpretable.
"""

from __future__ import annotations

import pytest

from sentinel.catalog.base import (
    Namespace,
    Registry,
    RuleResult,
    Severity,
    Verifiability,
    BaseRule,
    validate_registry,
)

pytestmark = pytest.mark.unit


def _rule(
    rule_id: str,
    *,
    severity: Severity = Severity.MUST,
    deprecated_in: str | None = None,
    superseded_by: str | None = None,
    citation: str = "https://modelcontextprotocol.io/specification/2026-07-28/basic",
    rationale: str = "",
) -> BaseRule:
    return BaseRule(
        id=rule_id,
        title="a title",
        severity=severity,
        citation=citation,
        rationale=rationale,
        verifiability=Verifiability.BLACK_BOX,
        remediation="Change the thing that is wrong, in this specific way.",
        check=lambda probe: RuleResult.passed(),
        fixtures=["nonconformant", "conformant"],
        deprecated_in=deprecated_in,
        superseded_by=superseded_by,
    )


def test_namespace_is_derived_from_the_id() -> None:
    assert _rule("MCP/2026-07-28/MUST/a").namespace is Namespace.MCP
    assert _rule("SENTINEL/STYLE/a", citation="", rationale="x" * 25).namespace is Namespace.SENTINEL


def test_slug_is_the_last_segment() -> None:
    assert _rule("MCP/2026-07-28/MUST/tools-are-named").slug == "tools-are-named"


def test_all_excludes_deprecated_rules_by_default() -> None:
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/live"))
    reg.register(_rule("MCP/2026-07-28/MUST/gone", deprecated_in="0.2.0",
                       superseded_by="MCP/2026-07-28/MUST/live"))

    assert [r.id for r in reg.all()] == ["MCP/2026-07-28/MUST/live"]
    assert len(reg.all(include_deprecated=True)) == 2


def test_by_severity_honours_include_deprecated() -> None:
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/live"))
    reg.register(_rule("MCP/2026-07-28/MUST/gone", deprecated_in="0.2.0",
                       superseded_by="MCP/2026-07-28/MUST/live"))

    assert len(reg.by_severity(Severity.MUST)) == 1
    assert len(reg.by_severity(Severity.MUST, include_deprecated=True)) == 2


def test_deprecated_rule_must_name_a_successor_that_exists() -> None:
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/gone", deprecated_in="0.2.0",
                       superseded_by="MCP/2026-07-28/SHOULD/nowhere"))

    problems = validate_registry(reg)
    assert any("superseded_by" in p.problem for p in problems)


def test_deprecated_rule_without_a_successor_is_a_problem() -> None:
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/gone", deprecated_in="0.2.0"))

    problems = validate_registry(reg)
    assert any("successor" in p.problem or "superseded_by" in p.problem for p in problems)


def test_two_live_rules_may_not_share_a_slug() -> None:
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/same-slug"))
    reg.register(_rule("MCP/2026-07-28/SHOULD/same-slug", severity=Severity.SHOULD))

    problems = validate_registry(reg)
    assert any("slug" in p.problem for p in problems)


def test_a_deprecated_rule_and_its_successor_may_share_a_slug() -> None:
    """This is the whole point of the mechanism."""
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/same-slug", deprecated_in="0.2.0",
                       superseded_by="MCP/2026-07-28/SHOULD/same-slug"))
    reg.register(_rule("MCP/2026-07-28/SHOULD/same-slug", severity=Severity.SHOULD))

    assert validate_registry(reg) == []


def test_sentinel_namespace_requires_a_rationale_and_no_citation() -> None:
    reg = Registry()
    reg.register(_rule("SENTINEL/STYLE/a", citation="", rationale=""))
    problems = validate_registry(reg)
    assert any("rationale" in p.problem for p in problems)

    reg2 = Registry()
    reg2.register(
        _rule("SENTINEL/STYLE/a",
              citation="https://modelcontextprotocol.io/specification/2026-07-28/basic",
              rationale="x" * 25)
    )
    assert any("citation" in p.problem for p in validate_registry(reg2))


def test_mcp_namespace_rejects_a_rationale() -> None:
    reg = Registry()
    reg.register(_rule("MCP/2026-07-28/MUST/a", rationale="x" * 25))
    assert any("rationale" in p.problem for p in validate_registry(reg))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/harness/test_lifecycle.py -q`
Expected: FAIL — `ImportError: cannot import name 'Namespace'`

- [ ] **Step 3: Implement the lifecycle in `base.py`**

Replace `RULE_ID_PATTERN` and add `Namespace` just above it:

```python
class Namespace(StrEnum):
    #: Rules that restate a normative requirement of the specification. These
    #: carry a citation and are what `--gate must` considers.
    MCP = "MCP"
    #: Rules this project believes in that the specification does not require.
    #: They carry a rationale instead of a citation, and no spec gate ever
    #: considers them -- a beyond-spec finding must never be mistakable for a
    #: conformance failure.
    SENTINEL = "SENTINEL"


#: `MCP/<revision>/<SEVERITY>/<slug>` or `SENTINEL/<CATEGORY>/<slug>`.
#:
#: Rule IDs are PERMANENT (§8.8). Once published, an id never changes meaning:
#: deprecate and add rather than redefine, or every historical report becomes
#: uninterpretable.
RULE_ID_PATTERN = re.compile(
    r"^(?:MCP/\d{4}-\d{2}-\d{2}/(?:MUST|SHOULD|MAY)"
    r"|SENTINEL/(?:SECURITY|STYLE|OPS))"
    r"/[a-z0-9][a-z0-9-]*$"
)
```

Add the fields to `BaseRule`, after `title`:

```python
    #: The sentinel version this rule first shipped in.
    introduced_in: str = "0.1.0"
    #: The sentinel version that deprecated it, or None while it is live. A
    #: deprecated rule is excluded from scans by default but keeps its id
    #: forever, so an archived report stays readable.
    deprecated_in: str | None = None
    #: The rule id that replaced it. Required when deprecated_in is set.
    superseded_by: str | None = None
    #: Why a beyond-spec rule exists. SENTINEL-namespace rules carry this
    #: INSTEAD of a citation -- a citation field pointing at nothing is how a
    #: catalog starts lying.
    rationale: str = ""

    @property
    def namespace(self) -> Namespace:
        return Namespace.SENTINEL if self.id.startswith("SENTINEL/") else Namespace.MCP

    @property
    def is_deprecated(self) -> bool:
        return self.deprecated_in is not None

    @property
    def slug(self) -> str:
        return self.id.rsplit("/", 1)[-1]
```

Replace `Registry.all` and `Registry.by_severity`:

```python
    def all(self, *, include_deprecated: bool = False) -> list[BaseRule]:
        # Sorted by id so a report's order is stable across runs and two reports
        # can be diffed.
        rules = self._rules.values()
        if not include_deprecated:
            rules = [r for r in rules if not r.is_deprecated]  # type: ignore[assignment]
        return sorted(rules, key=lambda r: r.id)

    def by_severity(
        self, severity: Severity, *, include_deprecated: bool = False
    ) -> list[BaseRule]:
        return [
            r
            for r in self.all(include_deprecated=include_deprecated)
            if r.severity is severity
        ]
```

Extend the `rule()` decorator signature with the four new keyword-only parameters (all defaulted) and pass them into `BaseRule(...)`:

```python
def rule(
    *,
    id: str,
    title: str,
    severity: Severity,
    verifiability: Verifiability,
    remediation: str,
    citation: str = "",
    rationale: str = "",
    fixtures: list[str] | None = None,
    introduced_in: str = "0.1.0",
    deprecated_in: str | None = None,
    superseded_by: str | None = None,
) -> Callable[[Callable[[Probe], RuleResult]], BaseRule]:
    """Declare and register a rule."""

    def decorate(check: Callable[[Probe], RuleResult]) -> BaseRule:
        return REGISTRY.register(
            BaseRule(
                id=id,
                title=title,
                severity=severity,
                citation=citation,
                rationale=rationale,
                verifiability=verifiability,
                remediation=remediation,
                check=check,
                fixtures=fixtures or [FIXTURE_NONCONFORMANT, FIXTURE_CONFORMANT],
                introduced_in=introduced_in,
                deprecated_in=deprecated_in,
                superseded_by=superseded_by,
            )
        )

    return decorate
```

Rewrite `validate_registry` to walk `all(include_deprecated=True)` — a deprecated rule that stops validating is still shipped — and to branch on namespace:

```python
def validate_registry(registry: Registry | None = None) -> list[ValidationProblem]:
    reg = registry if registry is not None else REGISTRY
    problems: list[ValidationProblem] = []
    known = {r.id for r in reg.all(include_deprecated=True)}
    live_slugs: dict[str, str] = {}

    for r in reg.all(include_deprecated=True):
        if not RULE_ID_PATTERN.match(r.id):
            problems.append(ValidationProblem(r.id, f"id does not match {RULE_ID_PATTERN.pattern}"))

        if r.namespace is Namespace.MCP:
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
            if r.rationale:
                problems.append(
                    ValidationProblem(
                        r.id,
                        "carries a rationale; an MCP rule restates the spec and cites it, "
                        "so a rationale means it belongs in the SENTINEL namespace",
                    )
                )
        else:
            if r.citation:
                problems.append(
                    ValidationProblem(
                        r.id, "carries a citation; a beyond-spec rule has nothing to cite"
                    )
                )
            if len(r.rationale) < 20:
                problems.append(
                    ValidationProblem(r.id, "has no rationale, or one too short to justify it")
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

        if r.is_deprecated:
            if not r.superseded_by:
                problems.append(
                    ValidationProblem(
                        r.id, "is deprecated but names no successor in superseded_by"
                    )
                )
            elif r.superseded_by not in known:
                problems.append(
                    ValidationProblem(
                        r.id, f"superseded_by names an unknown rule: {r.superseded_by}"
                    )
                )
        else:
            previous = live_slugs.get(r.slug)
            if previous is not None:
                problems.append(
                    ValidationProblem(
                        r.id, f"shares the live slug {r.slug!r} with {previous}"
                    )
                )
            live_slugs[r.slug] = r.id

        if r.verifiability is Verifiability.UNVERIFIABLE and r.severity is not Severity.MUST:
            problems.append(
                ValidationProblem(r.id, "is UNVERIFIABLE but not a MUST; nothing else needs the bucket")
            )

    return problems
```

Export `Namespace` from `catalog/__init__.py`'s import list and `__all__`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/harness/test_lifecycle.py -q && uv run pytest tests/harness -m unit -q && uv run sentinel catalog validate`
Expected: PASS; `catalog validate` still reports `35 rules validate: 33 MUST, 2 SHOULD`.

- [ ] **Step 5: Commit**

```bash
git checkout -b feat/wp-14-rule-lifecycle
git add harness/src/sentinel/catalog/base.py harness/src/sentinel/catalog/__init__.py tests/harness/test_lifecycle.py
git commit -m "feat: a rule lifecycle, so a wrong severity can be corrected without editing a published id"
```

---

### Task 2: Thread the lifecycle through scanning, the CLI and the reports

**Files:**
- Modify: `harness/src/sentinel/grade.py`
- Modify: `harness/src/sentinel/cli.py`
- Modify: `harness/src/sentinel/report/text.py`
- Modify: `harness/src/sentinel/report/json_report.py`
- Test: `tests/harness/test_lifecycle.py` (extend)

**Interfaces:**
- Consumes: `Namespace`, `Registry.all(include_deprecated=)`, `BaseRule.is_deprecated`, `BaseRule.superseded_by` from Task 1
- Produces:
  - `run_scan(endpoint, *, registry=None, timeout=10.0, bearer_token=None, only=None, include_deprecated=False) -> ScanReport`
  - `ScanReport.gate(severity)` counts only `Namespace.MCP` findings
  - CLI flag `--include-deprecated-rules` on `sentinel scan`

- [ ] **Step 1: Write the failing test**

Append to `tests/harness/test_lifecycle.py`:

```python
from sentinel.grade import Finding, ScanReport


def _finding(rule_id: str, outcome: Outcome, severity: Severity) -> Finding:
    return Finding(
        rule=_rule(
            rule_id,
            severity=severity,
            citation="" if rule_id.startswith("SENTINEL/") else
                     "https://modelcontextprotocol.io/specification/2026-07-28/basic",
            rationale="x" * 25 if rule_id.startswith("SENTINEL/") else "",
        ),
        result=RuleResult(outcome, "detail"),
        elapsed_s=0.0,
    )


def test_gate_ignores_the_beyond_spec_namespace() -> None:
    """A style opinion must never be able to fail a conformance gate."""
    report = ScanReport(
        endpoint="http://x/mcp",
        spec_revision="2026-07-28",
        findings=[
            _finding("MCP/2026-07-28/MUST/ok", Outcome.PASS, Severity.MUST),
            _finding("SENTINEL/STYLE/opinion", Outcome.FAIL, Severity.SHOULD),
        ],
        started_at=0.0,
        elapsed_s=0.0,
    )
    assert report.gate(Severity.MUST) == 0
    assert report.gate(Severity.SHOULD) == 0


def test_gate_still_fails_on_a_must_in_the_mcp_namespace() -> None:
    report = ScanReport(
        endpoint="http://x/mcp",
        spec_revision="2026-07-28",
        findings=[_finding("MCP/2026-07-28/MUST/bad", Outcome.FAIL, Severity.MUST)],
        started_at=0.0,
        elapsed_s=0.0,
    )
    assert report.gate(Severity.MUST) == 1
```

Add `Outcome` to the imports at the top of the file.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/harness/test_lifecycle.py -q -k gate`
Expected: FAIL — `assert 1 == 0`, because `gate` currently counts every FAIL of that severity regardless of namespace.

- [ ] **Step 3: Implement**

In `grade.py`, add `include_deprecated: bool = False` to `run_scan`'s keyword-only parameters and use it when listing rules:

```python
    rules = reg.all(include_deprecated=include_deprecated)
    if only is not None:
        rules = [r for r in rules if r.id in only]
```

Change `ScanReport.gate` to filter by namespace, and say why in a comment:

```python
    def gate(self, severity: Severity | None) -> int:
        """The process exit code for this report.

        Only the MCP namespace can fail a spec gate. A SENTINEL rule is an
        opinion this project holds and the specification does not; letting one
        fail `--gate must` would make a conformance verdict unfalsifiable.
        """
        if severity is None:
            return EXIT_OK
        failed = [
            f
            for f in self.by_outcome(Outcome.FAIL, severity)
            if f.rule.namespace is Namespace.MCP
        ]
        return EXIT_GATE_FAILED if failed else EXIT_OK
```

Import `Namespace` in `grade.py`.

In `cli.py`, add the flag to `scan()` and pass it through:

```python
    include_deprecated_rules: Annotated[
        bool,
        typer.Option(
            "--include-deprecated-rules",
            help=(
                "Also run rules this catalog has deprecated. Each is reported with the "
                "rule that replaced it, so an archived report stays reproducible."
            ),
        ),
    ] = False,
```

```python
        report = run_scan(
            endpoint,
            timeout=timeout,
            bearer_token=token,
            include_deprecated=include_deprecated_rules,
        )
```

In `report/text.py`, prefix a deprecated finding's line with `DEPRECATED ` and append `superseded by <id>` to its detail. In `report/json_report.py`, add `"deprecated": bool(f.rule.deprecated_in)`, `"supersededBy": f.rule.superseded_by`, and `"namespace": f.rule.namespace.value` to each finding object. Leave `schemaVersion` at `1`; the v2 bump is WP-24.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/harness -m unit -q && uv run mypy --strict harness/src/sentinel`
Expected: PASS, no type errors.

- [ ] **Step 5: Commit**

```bash
git add harness/src/sentinel/grade.py harness/src/sentinel/cli.py harness/src/sentinel/report tests/harness/test_lifecycle.py
git commit -m "feat: --include-deprecated-rules, and a gate that only the MCP namespace can fail"
```

---

### Task 3: The probe stops sending malformed requests

**Files:**
- Modify: `harness/src/sentinel/probe/client.py`
- Test: `tests/harness/test_probe_meta.py` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces:
  - `CLIENT_CAPABILITIES: dict[str, Any]` — module constant, `{}`
  - `Probe.meta(*, version=_UNSET, omit_client_capabilities=False, client_capabilities=_UNSET) -> dict[str, Any]`
  - `Probe.build(..., omit_client_capabilities=False, client_capabilities=_UNSET, omit_protocol_version_header=False, protocol_version_header: str | None = None)`
  - `HEADER_PROTOCOL_VERSION = "MCP-Protocol-Version"`, `ACCEPT_VALUE = "application/json, text/event-stream"`
  - `Transport.send` sends `Accept: application/json, text/event-stream` on every request
  - `Probe.new_connection() -> Probe`

**Why — three separate omissions, all of the same class.** The probe is supposed to be *literal*, not *wrong*. Today it omits three things the specification requires of a client, and each one is grounds for a conformant server to reject every request the harness sends:

1. *"`io.modelcontextprotocol/clientCapabilities` — Required: **Yes**"* — `client.py` imports `KEY_CLIENT_CAPABILITIES` and never sets it.
2. *"Every POST request to the MCP endpoint **MUST** include an `MCP-Protocol-Version` header."* The probe sends `Mcp-Method` and `Mcp-Name` and nothing else. A server enforcing this returns `400` + `-32020 HeaderMismatch` to **every** request, and the harness would report a perfectly conformant server as catastrophically broken.
3. *"The client **MUST** include an `Accept` header listing both `application/json` and `text/event-stream` as supported content types."*

This is the single most consequential bug in the harness, and it is invisible today only because neither fixture enforces any of the three.

- [ ] **Step 1: Write the failing test**

Create `tests/harness/test_probe_meta.py`:

```python
"""The probe's own conformance.

A scanner that sends malformed requests grades every server as broken. The
spec's per-request `_meta` table marks protocolVersion and clientCapabilities
Required: Yes, and clientInfo Required: No.
"""

from __future__ import annotations

import json

import pytest

from sentinel.probe.client import (
    KEY_CLIENT_CAPABILITIES,
    KEY_CLIENT_INFO,
    KEY_PROTOCOL_VERSION,
    Probe,
)

pytestmark = pytest.mark.unit


def _meta_of(probe: Probe, **overrides: object) -> dict[str, object]:
    request = probe.build("tools/list", **overrides)  # type: ignore[arg-type]
    body = json.loads(request.body())
    return body["params"]["_meta"]


def test_every_request_carries_client_capabilities() -> None:
    with Probe("http://unused.invalid/mcp") as probe:
        meta = _meta_of(probe)
    assert KEY_CLIENT_CAPABILITIES in meta
    assert meta[KEY_CLIENT_CAPABILITIES] == {}


def test_every_request_carries_the_protocol_version() -> None:
    with Probe("http://unused.invalid/mcp") as probe:
        meta = _meta_of(probe)
    assert meta[KEY_PROTOCOL_VERSION] == "2026-07-28"


def test_client_info_is_still_sent() -> None:
    with Probe("http://unused.invalid/mcp") as probe:
        meta = _meta_of(probe)
    assert meta[KEY_CLIENT_INFO]["name"] == "sentinel-probe"


def test_client_capabilities_can_be_omitted_on_purpose() -> None:
    """A rule needs to send a deliberately malformed request to test the MUST."""
    with Probe("http://unused.invalid/mcp") as probe:
        meta = _meta_of(probe, omit_client_capabilities=True)
    assert KEY_CLIENT_CAPABILITIES not in meta


def test_client_capabilities_can_be_overridden() -> None:
    with Probe("http://unused.invalid/mcp") as probe:
        meta = _meta_of(probe, client_capabilities={"elicitation": {}})
    assert meta[KEY_CLIENT_CAPABILITIES] == {"elicitation": {}}


def test_every_request_carries_the_protocol_version_header() -> None:
    """"Every POST request to the MCP endpoint MUST include an
    MCP-Protocol-Version header." A server enforcing this rejects every
    request the harness sends today with 400 + HeaderMismatch."""
    with Probe("http://unused.invalid/mcp") as probe:
        request = probe.build("tools/list")
    assert request.headers["MCP-Protocol-Version"] == "2026-07-28"


def test_the_protocol_version_header_matches_the_body() -> None:
    """"The header value MUST match the io.modelcontextprotocol/protocolVersion
    field carried in the request body's _meta.""""
    with Probe("http://unused.invalid/mcp") as probe:
        request = probe.build("tools/list")
    body = json.loads(request.body())
    assert request.headers["MCP-Protocol-Version"] == body["params"]["_meta"][KEY_PROTOCOL_VERSION]


def test_the_protocol_version_header_can_be_omitted_or_forced_apart() -> None:
    with Probe("http://unused.invalid/mcp") as probe:
        assert "MCP-Protocol-Version" not in probe.build(
            "tools/list", omit_protocol_version_header=True
        ).headers
        skewed = probe.build("tools/list", protocol_version_header="2025-11-25")
    assert skewed.headers["MCP-Protocol-Version"] == "2025-11-25"
    assert json.loads(skewed.body())["params"]["_meta"][KEY_PROTOCOL_VERSION] == "2026-07-28"


def test_the_accept_header_lists_both_content_types() -> None:
    """"The client MUST include an Accept header listing both application/json
    and text/event-stream as supported content types.""""
    from sentinel.probe.transport import ACCEPT_VALUE

    assert "application/json" in ACCEPT_VALUE
    assert "text/event-stream" in ACCEPT_VALUE


def test_new_connection_is_a_separate_client_to_the_same_endpoint() -> None:
    """`tools-list-connection-independent` needs two genuinely separate clients."""
    with Probe("http://unused.invalid/mcp", bearer_token="t", timeout=3.0) as a:
        b = a.new_connection()
        try:
            assert b.endpoint == a.endpoint
            assert b is not a
            assert b._transport is not a._transport
            assert b._transport.bearer_token == "t"
            assert b._transport.timeout == 3.0
            assert b.protocol_version == a.protocol_version
        finally:
            b.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/harness/test_probe_meta.py -q`
Expected: FAIL — `assert 'io.modelcontextprotocol/clientCapabilities' in {...}`

- [ ] **Step 3: Implement**

In `client.py`, add the constant beside `CLIENT_INFO`:

```python
CLIENT_INFO = {"name": "sentinel-probe", "version": "0.1.0"}

#: The probe declares no client capabilities, which is the truth: it cannot
#: sample, elicit, or serve roots. Declaring capabilities it does not have would
#: invite servers into MRTR flows the probe cannot complete, and the spec is
#: explicit that a server MUST NOT ask for a capability the client did not
#: declare -- which is itself a rule worth being able to test.
CLIENT_CAPABILITIES: dict[str, Any] = {}
```

Replace `meta()`:

```python
    def meta(
        self,
        *,
        version: Any = _UNSET,
        omit_client_capabilities: bool = False,
        client_capabilities: Any = _UNSET,
    ) -> dict[str, Any]:
        """Build a `_meta` object.

        `protocolVersion` and `clientCapabilities` are Required: Yes on every
        request; `clientInfo` is Required: No but SHOULD be sent, so it is.

        `version=None` omits the protocol version entirely -- the unversioned
        case §8.1 treats as a legacy fallback -- which is different from not
        passing the argument at all. `omit_client_capabilities` is the same idea
        for the other required field: a rule that tests the MUST has to be able
        to break it deliberately.
        """
        meta: dict[str, Any] = {KEY_CLIENT_INFO: CLIENT_INFO}
        resolved = self.protocol_version if version is _UNSET else version
        if resolved is not None:
            meta[KEY_PROTOCOL_VERSION] = resolved
        if not omit_client_capabilities:
            meta[KEY_CLIENT_CAPABILITIES] = (
                CLIENT_CAPABILITIES if client_capabilities is _UNSET else client_capabilities
            )
        return meta
```

Add the two parameters to `build()` and thread them into the `meta()` call:

```python
        omit_client_capabilities: bool = False,
        client_capabilities: Any = _UNSET,
```
```python
        if include_meta:
            body_params["_meta"] = self.meta(
                version=version,
                omit_client_capabilities=omit_client_capabilities,
                client_capabilities=client_capabilities,
            )
```

Add the protocol-version header. In `client.py`, beside the other header constants:

```python
HEADER_MCP_METHOD = "Mcp-Method"
HEADER_MCP_NAME = "Mcp-Name"
#: Required on EVERY POST, and its value MUST match the protocolVersion in the
#: body's _meta. A server enforcing this rejects a request without it outright,
#: which means a probe that omits it cannot grade anything.
HEADER_PROTOCOL_VERSION = "MCP-Protocol-Version"
```

and in `build()`, after the `Mcp-Name` block and before `built.update(headers or {})`:

```python
        if not omit_protocol_version_header:
            declared = self.meta(version=version).get(KEY_PROTOCOL_VERSION)
            resolved_header = (
                protocol_version_header
                if protocol_version_header is not None
                else declared
            )
            # When the caller asked for an unversioned body there is nothing for
            # the header to agree with, so sending one would manufacture the
            # very mismatch the header rule exists to detect.
            if resolved_header is not None:
                built[HEADER_PROTOCOL_VERSION] = str(resolved_header)
```

with the two parameters added to `build()`'s signature:

```python
        omit_protocol_version_header: bool = False,
        protocol_version_header: str | None = None,
```

In `transport.py`, add the constant and send it:

```python
#: "The client MUST include an Accept header listing both application/json and
#: text/event-stream as supported content types."
ACCEPT_VALUE = "application/json, text/event-stream"
```

```python
    def send(self, request: Request) -> RawResponse:
        headers = {
            "Content-Type": "application/json",
            "Accept": ACCEPT_VALUE,
            **request.headers,
        }
```

Add `new_connection()` after `__exit__`:

```python
    def new_connection(self) -> Probe:
        """A second probe to the same endpoint over a separate HTTP client.

        The specification says a list result "MUST NOT vary per-connection".
        Proving that needs two connections; a rule holding one `Probe` has one.
        The caller owns the returned probe and must close it.
        """
        return Probe(
            self.endpoint,
            timeout=self._transport.timeout,
            bearer_token=self._transport.bearer_token,
            protocol_version=self.protocol_version,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/harness -m unit -q`
Expected: PASS. The fixture servers do not require `clientCapabilities`, so no existing test changes.

- [ ] **Step 5: Commit**

```bash
git add harness/src/sentinel/probe tests/harness/test_probe_meta.py
git commit -m "fix: the probe was sending malformed requests

Three omissions, each grounds for a conformant server to reject every request
the harness sends:

  * clientCapabilities is Required: Yes on every request. client.py imported
    the key and never set it.
  * 'Every POST request to the MCP endpoint MUST include an
    MCP-Protocol-Version header.' The probe sent Mcp-Method and Mcp-Name and
    nothing else, so a server enforcing this would answer 400 HeaderMismatch
    to everything -- and the harness would report it as broken.
  * 'The client MUST include an Accept header listing both application/json
    and text/event-stream.'

Literal is the point; wrong is not. Each override is preserved so a rule can
still break one field deliberately."
```

---

### Task 4: The three severity corrections

**Files:**
- Create: `harness/src/sentinel/catalog/checks.py`
- Create: `harness/src/sentinel/catalog/should/envelope.py`
- Create: `harness/src/sentinel/catalog/beyond/__init__.py`
- Create: `harness/src/sentinel/catalog/beyond/style.py`
- Modify: `harness/src/sentinel/catalog/must/envelope.py`
- Modify: `harness/src/sentinel/catalog/should/ordering.py`
- Modify: `harness/src/sentinel/catalog/should/__init__.py`
- Modify: `harness/src/sentinel/catalog/__init__.py`
- Modify: `harness/src/sentinel/__init__.py` (version to `0.2.0`)
- Test: `tests/harness/test_lifecycle.py` (extend)

**Interfaces:**
- Consumes: `Namespace`, lifecycle fields, `validate_registry` from Task 1
- Produces:
  - `sentinel.catalog.checks.server_info_echoed(probe) -> RuleResult`
  - `sentinel.catalog.checks.tools_list_deterministic(probe) -> RuleResult`
  - `sentinel.catalog.checks.tools_sorted_by_name(probe) -> RuleResult`
  - Live rules `MCP/2026-07-28/SHOULD/server-info-echoed`, `MCP/2026-07-28/SHOULD/tools-list-is-deterministic`, `SENTINEL/STYLE/tools-sorted-by-name`
  - Deprecated rules `MCP/2026-07-28/MUST/server-info-echoed`, `MCP/2026-07-28/MUST/tools-list-is-deterministic`, `MCP/2026-07-28/SHOULD/tools-sorted-by-name`

**Why, quoted:** `io.modelcontextprotocol/serverInfo` is *"Required: **No**"* under *"Servers **SHOULD** include the following… field in every result's `_meta`"*. Tool ordering is *"Servers **SHOULD** return tools in a deterministic order"*. And the spec asks for *deterministic*, never for *sorted* — a stable but unsorted list conforms fully, so `tools-sorted-by-name` is not a spec rule at any severity.

- [ ] **Step 1: Write the failing test**

Append to `tests/harness/test_lifecycle.py`:

```python
from sentinel.catalog import REGISTRY  # noqa: E402
import sentinel.catalog  # noqa: F401,E402  -- import registers every rule


CORRECTIONS = [
    ("MCP/2026-07-28/MUST/server-info-echoed", "MCP/2026-07-28/SHOULD/server-info-echoed"),
    (
        "MCP/2026-07-28/MUST/tools-list-is-deterministic",
        "MCP/2026-07-28/SHOULD/tools-list-is-deterministic",
    ),
    ("MCP/2026-07-28/SHOULD/tools-sorted-by-name", "SENTINEL/STYLE/tools-sorted-by-name"),
]


@pytest.mark.parametrize(("old", "new"), CORRECTIONS)
def test_wrongly_graded_rules_are_deprecated_not_edited(old: str, new: str) -> None:
    by_id = {r.id: r for r in REGISTRY.all(include_deprecated=True)}
    assert old in by_id, f"{old} was deleted; ids are permanent"
    assert by_id[old].is_deprecated
    assert by_id[old].superseded_by == new
    assert new in by_id
    assert not by_id[new].is_deprecated


def test_the_deprecated_rules_are_not_scanned_by_default() -> None:
    live = {r.id for r in REGISTRY.all()}
    for old, new in CORRECTIONS:
        assert old not in live
        assert new in live


def test_the_shipped_catalog_validates() -> None:
    assert validate_registry(REGISTRY) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/harness/test_lifecycle.py -q -k "wrongly_graded or not_scanned"`
Expected: FAIL — `assert False` on `is_deprecated`, and `KeyError`/`assert` on the successors, which do not exist yet.

- [ ] **Step 3: Implement**

Bump `harness/src/sentinel/__init__.py`: `__version__ = "0.2.0"`.

Create `harness/src/sentinel/catalog/checks.py` and move the three check bodies into it verbatim — no behaviour change, only relocation, so a deprecated rule and its successor cannot drift apart:

```python
"""Check functions shared between a deprecated rule and its successor.

When a rule's severity turns out to be wrong, the id is deprecated and a new one
published (HANDOFF §8.8). Both then need the same check. Keeping the function
here rather than duplicating it means the pair cannot silently disagree about
what it is measuring -- which would make the deprecation notice a lie.
"""

from __future__ import annotations

import hashlib

from sentinel.catalog.base import RuleResult
from sentinel.probe.client import KEY_SERVER_INFO, Probe

LIST_ENDPOINT_NAMES = [
    "server/discover",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
]


def server_info_echoed(probe: Probe) -> RuleResult:
    senders = [
        ("server/discover", probe.discover),
        ("tools/list", probe.tools_list),
        ("resources/list", probe.resources_list),
        ("resources/templates/list", probe.resource_templates_list),
        ("prompts/list", probe.prompts_list),
    ]
    missing: list[str] = []
    checked = 0

    for name, send in senders:
        result = send().result()
        if result is None:
            continue
        checked += 1
        meta = result.get("_meta")
        info = meta.get(KEY_SERVER_INFO) if isinstance(meta, dict) else None
        if not isinstance(info, dict) or not info.get("name"):
            top = result.get("serverInfo")
            if isinstance(top, dict) and top.get("name"):
                continue
            missing.append(name)

    if checked == 0:
        return RuleResult.indeterminate("no endpoint returned a result to inspect")
    if missing:
        return RuleResult.failed(
            f"{len(missing)} of {checked} results omit serverInfo: {missing}",
            evidence=f"endpoints missing serverInfo: {missing}",
        )
    return RuleResult.passed(f"all {checked} results echo serverInfo")


def tools_list_deterministic(probe: Probe) -> RuleResult:
    # Twenty calls, not one hundred: enough that map iteration order will differ
    # if it is going to, without making a scan slow against a remote server.
    # The broker's own test suite runs the full hundred.
    digests: set[str] = set()
    orders: set[str] = set()

    for _ in range(20):
        result = probe.tools_list().result()
        if result is None:
            return RuleResult.not_applicable("tools/list did not return a result")
        tools = result.get("tools")
        if not isinstance(tools, list):
            return RuleResult.failed(f"tools is not an array: {tools!r}")
        names = [t.get("name") for t in tools if isinstance(t, dict)]
        orders.add(",".join(str(n) for n in names))
        digests.add(hashlib.sha256(str(tools).encode()).hexdigest())

    if len(orders) > 1:
        return RuleResult.failed(
            f"tools/list returned {len(orders)} different orderings across 20 calls",
            evidence=f"orderings observed: {sorted(orders)[:3]}",
        )
    if len(digests) > 1:
        return RuleResult.failed(
            f"tools/list returned {len(digests)} different tool payloads across 20 calls "
            "with the same ordering; some field varies between calls",
            evidence=f"{len(digests)} distinct digests",
        )
    return RuleResult.passed("20 calls to tools/list produced one distinct payload")


def tools_sorted_by_name(probe: Probe) -> RuleResult:
    result = probe.tools_list().result()
    if result is None:
        return RuleResult.not_applicable("tools/list did not return a result")

    tools = result.get("tools")
    if not isinstance(tools, list) or len(tools) < 2:
        return RuleResult.not_applicable("fewer than two tools to order")

    names = [t.get("name", "") for t in tools if isinstance(t, dict)]
    ordered = sorted(names, key=lambda n: str(n).encode())
    if names != ordered:
        return RuleResult.failed(
            f"tools are not in byte-wise name order: {names} (byte-wise would be {ordered})",
            evidence=f"served {names}, byte-wise {ordered}",
        )
    return RuleResult.passed(f"{len(names)} tools are in byte-wise name order")
```

In `must/envelope.py`, replace the `@rule(...)`-decorated `server_info_echoed` and `tools_list_deterministic` definitions with deprecated declarations that delegate. Keep every other field byte-identical so an archived report still renders the same text:

```python
from sentinel.catalog import checks

@rule(
    id="MCP/2026-07-28/MUST/server-info-echoed",
    title="Every result echoes serverInfo",
    severity=Severity.MUST,
    citation=f"{BASIC}/index#meta",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Echo io.modelcontextprotocol/serverInfo in each result's _meta. Clients key cache "
        "entries on the (name, version) pair, so a result that omits it cannot be cached "
        "and cannot be attributed if it is logged."
    ),
    deprecated_in="0.2.0",
    superseded_by="MCP/2026-07-28/SHOULD/server-info-echoed",
)
def server_info_echoed_deprecated(probe: Probe) -> RuleResult:
    # Graded MUST in 0.1.0. The specification marks serverInfo "Required: No"
    # under "Servers SHOULD include the following field in every result's
    # _meta", so this demanded more than the spec does -- exactly the false
    # positive MEASUREMENTS.md publishes as zero. Superseded, not edited,
    # because ids are permanent.
    return checks.server_info_echoed(probe)
```

```python
@rule(
    id="MCP/2026-07-28/MUST/tools-list-is-deterministic",
    title="tools/list is byte-stable across repeated calls",
    severity=Severity.MUST,
    citation=f"{SPEC_BASE}/server/tools#capabilities",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Build the tool manifest once, sort it by name byte-wise, and serve the "
        "precomputed bytes. A manifest that reorders between calls invalidates every "
        "downstream client's cache and destroys LLM prompt-cache hit rates."
    ),
    deprecated_in="0.2.0",
    superseded_by="MCP/2026-07-28/SHOULD/tools-list-is-deterministic",
)
def tools_list_deterministic_deprecated(probe: Probe) -> RuleResult:
    # Graded MUST in 0.1.0. "Servers SHOULD return tools in a deterministic
    # order" is a SHOULD. The MUST in the same paragraph is a different
    # property -- "MUST NOT vary per-connection" -- which this never tested,
    # because all twenty calls shared one connection. See
    # MCP/2026-07-28/MUST/tools-list-connection-independent.
    return checks.tools_list_deterministic(probe)
```

Delete the now-unused `KEY_SERVER_INFO` import from `must/envelope.py` if nothing else there uses it, and add `from sentinel.catalog.base import SPEC_BASE` if not already imported.

Create `harness/src/sentinel/catalog/should/envelope.py`:

```python
"""SHOULD rules for the result envelope.

Both rules here were graded MUST in 0.1.0 and are corrections, not additions.
The specification grades each of them SHOULD, and a harness that demands more
than the specification is producing exactly the false positive MEASUREMENTS.md
publishes as zero.
"""

from __future__ import annotations

from sentinel.catalog import checks
from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe


@rule(
    id="MCP/2026-07-28/SHOULD/server-info-echoed",
    title="Every result echoes serverInfo",
    severity=Severity.SHOULD,
    citation=f"{SPEC_BASE}/basic/index#meta",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Echo io.modelcontextprotocol/serverInfo in each result's _meta. The spec marks it "
        "Required: No, so omitting it is legal -- but clients use the (name, version) pair "
        "to attribute a logged result and to key a cache entry, and neither is possible "
        "without it."
    ),
    introduced_in="0.2.0",
)
def server_info_echoed(probe: Probe) -> RuleResult:
    return checks.server_info_echoed(probe)


@rule(
    id="MCP/2026-07-28/SHOULD/tools-list-is-deterministic",
    title="tools/list is byte-stable across repeated calls",
    severity=Severity.SHOULD,
    citation=f"{SPEC_BASE}/server/tools#capabilities",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Build the tool manifest once and serve the precomputed bytes. Any stable order "
        "satisfies this; the spec asks for determinism, not for a particular order. A "
        "manifest that reorders between calls invalidates every downstream client's cache "
        "and destroys LLM prompt-cache hit rates."
    ),
    introduced_in="0.2.0",
)
def tools_list_is_deterministic(probe: Probe) -> RuleResult:
    return checks.tools_list_deterministic(probe)
```

In `should/ordering.py`, replace the `tools_sorted` declaration with a deprecated one delegating to `checks.tools_sorted_by_name`, `deprecated_in="0.2.0"`, `superseded_by="SENTINEL/STYLE/tools-sorted-by-name"`, keeping every other field as-is. Leave `tools-have-descriptions` untouched.

Create `harness/src/sentinel/catalog/beyond/__init__.py`:

```python
"""Rules this project believes in that the specification does not require.

They live in their own `SENTINEL/` namespace and carry a `rationale` instead of
a `citation`, because a citation field pointing at nothing is how a catalog
starts lying. No spec gate ever considers them: `--gate must` and
`--gate should` filter to the MCP namespace, so a style opinion can never be
mistaken for a conformance failure.
"""

from __future__ import annotations

from sentinel.catalog.beyond import style

__all__ = ["style"]
```

Create `harness/src/sentinel/catalog/beyond/style.py`:

```python
"""Beyond-spec style checks."""

from __future__ import annotations

from sentinel.catalog import checks
from sentinel.catalog.base import RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe


@rule(
    id="SENTINEL/STYLE/tools-sorted-by-name",
    title="tools/list returns tools in byte-wise name order",
    severity=Severity.SHOULD,
    rationale=(
        "The specification asks for a deterministic order and says nothing about which "
        "order. A stable but unsorted manifest conforms fully. Byte-wise name order is "
        "worth having anyway: it means two deployments advertising the same tools produce "
        "the same manifest bytes, which is what makes a manifest hash comparable across "
        "environments -- and comparable hashes are what drift detection runs on."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Sort tools by name byte-wise (not case-insensitively, not by locale collation)."
    ),
    introduced_in="0.2.0",
)
def tools_sorted_by_name(probe: Probe) -> RuleResult:
    return checks.tools_sorted_by_name(probe)
```

Update `should/__init__.py` to `from sentinel.catalog.should import envelope, ordering` with a matching `__all__`, and `catalog/__init__.py` to `from sentinel.catalog import beyond, must, should` with `beyond` added to `__all__`.

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
uv run pytest tests/harness -m unit -q
uv run sentinel catalog validate
uv run sentinel catalog list --severity should
```
Expected: PASS. `catalog validate` reports **35 rules validate: 31 MUST, 4 SHOULD** (33 MUST − 2 deprecated; 2 SHOULD − 1 deprecated + 2 new + 1 beyond-spec). The three deprecated rules are excluded from the count because `all()` excludes them; `--include-deprecated-rules` brings them back.

> If `test_fixture_oracle.py` now reports fewer detected violations, that is expected and Step 5 of Task 7 reconciles `SEEDED_VIOLATIONS`. Do not weaken the oracle test to make it pass.

- [ ] **Step 5: Commit**

```bash
git add harness/src/sentinel tests/harness/test_lifecycle.py
git commit -m "fix: three rules graded a SHOULD as a MUST, or invented a requirement

serverInfo is Required: No under 'Servers SHOULD include'. Tool ordering is
'Servers SHOULD return tools in a deterministic order'. And the spec asks for
deterministic, never for sorted -- a stable but unsorted manifest conforms
fully, so tools-sorted-by-name was not a spec rule at any severity and moves to
the beyond-spec namespace.

Ids are permanent, so all three are deprecated and superseded rather than
edited. --include-deprecated-rules reproduces an archived report."
```

---

### Task 5: The MUST the deterministic-ordering rule was standing in for

**Files:**
- Modify: `harness/src/sentinel/catalog/must/envelope.py`
- Test: `tests/harness/test_catalog.py` (extend)

**Interfaces:**
- Consumes: `Probe.new_connection()` from Task 3
- Produces: live rule `MCP/2026-07-28/MUST/tools-list-connection-independent`

**Why, quoted:** *"This set **MAY** be empty and **MAY** change over time… but **MUST NOT** vary per-connection or as a side effect of other requests on the connection. The set **MAY** vary by the authorization presented on the request."* So the comparison holds the credential constant and compares membership, not order — order is the SHOULD, and one defect should not fail two rules.

- [ ] **Step 1: Write the failing test**

Append to `tests/harness/test_catalog.py`:

```python
def test_connection_independence_rule_exists_and_passes_the_conformant_fixture(
    conformant_endpoint: str,
) -> None:
    from sentinel.catalog.base import REGISTRY, Outcome
    from sentinel.probe.client import Probe

    by_id = {r.id: r for r in REGISTRY.all()}
    rule = by_id["MCP/2026-07-28/MUST/tools-list-connection-independent"]

    with Probe(conformant_endpoint) as probe:
        result = rule.evaluate(probe)

    assert result.outcome is Outcome.PASS, result.detail
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/harness/test_catalog.py -q -k connection_independence`
Expected: FAIL — `KeyError: 'MCP/2026-07-28/MUST/tools-list-connection-independent'`

- [ ] **Step 3: Implement**

Append to `must/envelope.py`:

```python
@rule(
    id="MCP/2026-07-28/MUST/tools-list-connection-independent",
    title="tools/list does not vary between connections",
    severity=Severity.MUST,
    citation=f"{SPEC_BASE}/server/tools#capabilities",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Build the tool set from the request's credential and nothing else. If the set "
        "differs between two connections presenting the same token, something "
        "connection-shaped is feeding it -- a cached handshake, a per-socket registry, a "
        "first-request initialisation. That is the state this revision removed."
    ),
    introduced_in="0.2.0",
)
def tools_list_connection_independent(probe: Probe) -> RuleResult:
    import json

    def canonical(tools: object) -> list[str] | None:
        if not isinstance(tools, list):
            return None
        # Membership, not order. Order is graded SHOULD by
        # MCP/2026-07-28/SHOULD/tools-list-is-deterministic; making one defect
        # fail two rules would double-count it.
        return sorted(json.dumps(t, sort_keys=True, separators=(",", ":")) for t in tools)

    first = probe.tools_list().result()
    if first is None:
        return RuleResult.not_applicable("tools/list did not return a result")
    here = canonical(first.get("tools"))
    if here is None:
        return RuleResult.failed(f"tools is not an array: {first.get('tools')!r}")

    # A second probe to the same endpoint with the SAME credential. The spec
    # permits the set to vary by authorization, so varying the token would test
    # the wrong thing.
    other = probe.new_connection()
    try:
        second = other.tools_list().result()
    finally:
        other.close()

    if second is None:
        return RuleResult.indeterminate(
            "the second connection returned no result; cannot compare"
        )
    there = canonical(second.get("tools"))
    if there is None:
        return RuleResult.failed(
            f"the second connection returned a non-array tools field: "
            f"{second.get('tools')!r}"
        )

    if here != there:
        only_here = [t for t in here if t not in there]
        only_there = [t for t in there if t not in here]
        return RuleResult.failed(
            f"tools/list returned {len(here)} tools on one connection and "
            f"{len(there)} on another with the same credential; the set varies "
            "per-connection",
            evidence=(
                f"only on connection A: {only_here[:2]}; "
                f"only on connection B: {only_there[:2]}"
            ),
        )
    return RuleResult.passed(
        f"two independent connections returned the same {len(here)} tools"
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/harness -m unit -q && uv run sentinel catalog validate`
Expected: PASS; `36 rules validate: 32 MUST, 4 SHOULD`.

- [ ] **Step 5: Commit**

```bash
git add harness/src/sentinel/catalog/must/envelope.py tests/harness/test_catalog.py
git commit -m "feat: test the MUST that deterministic-ordering was standing in for

'MUST NOT vary per-connection' needs two connections. The deprecated rule made
twenty calls on one."
```

---

### Task 6: Deprecation windows the registry can actually express

**Files:**
- Modify: `harness/src/sentinel/catalog/deprecations.py`
- Create: `tests/harness/data/deprecation_registry.json`
- Test: `tests/harness/test_removal_windows.py` (create)
- Modify: `tests/harness/test_deprecations.py` (reconcile any assertion on the old dates)

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces:
  - `FixedRevision(on_or_after: date)`, `FollowsFeature(feature_id: str, sep: str = "")`, `AfterEvent(description: str, sep: str = "")`
  - `RemovalWindow = FixedRevision | FollowsFeature | AfterEvent`
  - `DeprecatedFeature.deprecated_on: date` (no default) and `DeprecatedFeature.removal: RemovalWindow`
  - `resolve_removal(feature: DeprecatedFeature, by_id: dict[str, DeprecatedFeature]) -> FixedRevision | AfterEvent`
  - `Inventory.months_remaining(detection) -> int | None` — `None` when the window is event-relative

**Why:** the registry, fetched verbatim, disagrees with the code on two of six features, and two of the removal conditions are not date arithmetic at all: `includeContext` is *"Follows Sampling (SEP-2577)"* and HTTP+SSE is *"Three months after SEP-2596 reaches Final"* — an event that has not happened. Inventing a date for it is the same failure as scoring an unverifiable MUST as a pass.

- [ ] **Step 1: Write the failing test**

Create `tests/harness/data/deprecation_registry.json` — transcribed from the registry, not computed:

```json
{
  "source": "https://modelcontextprotocol.io/specification/2026-07-28/deprecated",
  "fetched_on": "2026-08-23",
  "note": "Transcribed verbatim. If the registry changes, this file changes and the test that reads it says so.",
  "features": [
    {"id": "roots", "sep": "SEP-2577", "deprecated_in": "2026-07-28",
     "earliest_removal": "First revision released on or after 2027-07-28"},
    {"id": "sampling", "sep": "SEP-2577", "deprecated_in": "2026-07-28",
     "earliest_removal": "First revision released on or after 2027-07-28"},
    {"id": "logging", "sep": "SEP-2577", "deprecated_in": "2026-07-28",
     "earliest_removal": "First revision released on or after 2027-07-28"},
    {"id": "oauth-dcr", "sep": "PR #2858", "deprecated_in": "2026-07-28",
     "earliest_removal": "First revision released on or after 2027-07-28"},
    {"id": "include-context", "sep": "SEP-2596", "deprecated_in": "2025-11-25",
     "earliest_removal": "Follows Sampling (SEP-2577)"},
    {"id": "http-sse", "sep": "SEP-2596", "deprecated_in": "2025-03-26",
     "earliest_removal": "Three months after SEP-2596 reaches Final"}
  ]
}
```

Create `tests/harness/test_removal_windows.py`:

```python
"""The deprecation inventory reports what the registry says, not what is convenient.

Two of the six removal conditions are not date arithmetic: includeContext's
window follows Sampling's, and HTTP+SSE's depends on an event that has not
happened. A model that can only express `deprecated_on + 12 months` has to
invent a date for both -- and an invented date in a migration report is the same
failure as scoring an unverifiable MUST as a pass.
"""

from __future__ import annotations

import datetime
import json
import pathlib

import pytest

from sentinel.catalog.deprecations import (
    FEATURES,
    FEATURES_BY_ID,
    AfterEvent,
    FixedRevision,
    FollowsFeature,
    Inventory,
    Detection,
    Confidence,
    resolve_removal,
)

pytestmark = pytest.mark.unit

REGISTRY = json.loads(
    (pathlib.Path(__file__).parent / "data" / "deprecation_registry.json").read_text()
)


@pytest.mark.parametrize("row", REGISTRY["features"], ids=lambda r: r["id"])
def test_deprecated_on_matches_the_registry(row: dict[str, str]) -> None:
    feature = FEATURES_BY_ID[row["id"]]
    assert feature.deprecated_on == datetime.date.fromisoformat(row["deprecated_in"])


def test_every_registry_row_has_a_feature_and_vice_versa() -> None:
    assert {r["id"] for r in REGISTRY["features"]} == set(FEATURES_BY_ID)


def test_include_context_follows_sampling() -> None:
    assert FEATURES_BY_ID["include-context"].removal == FollowsFeature(
        feature_id="sampling", sep="SEP-2577"
    )
    resolved = resolve_removal(FEATURES_BY_ID["include-context"], FEATURES_BY_ID)
    assert resolved == FixedRevision(datetime.date(2027, 7, 28))


def test_http_sse_removal_is_an_event_and_no_date_is_invented() -> None:
    window = FEATURES_BY_ID["http-sse"].removal
    assert isinstance(window, AfterEvent)
    assert window.sep == "SEP-2596"
    assert "Final" in window.describe()
    # And nothing anywhere turns it into a date.
    assert not hasattr(window, "on_or_after")


def test_months_remaining_is_none_for_an_event_relative_window() -> None:
    detection = Detection(
        feature=FEATURES_BY_ID["http-sse"], in_use=True, confidence=Confidence.OBSERVED
    )
    inventory = Inventory(
        endpoint="http://x/mcp", as_of=datetime.date(2026, 8, 23), detections=[detection]
    )
    assert inventory.months_remaining(detection) is None


def test_months_remaining_is_computed_for_a_fixed_window() -> None:
    detection = Detection(
        feature=FEATURES_BY_ID["roots"], in_use=True, confidence=Confidence.OBSERVED
    )
    inventory = Inventory(
        endpoint="http://x/mcp", as_of=datetime.date(2026, 8, 23), detections=[detection]
    )
    assert inventory.months_remaining(detection) == 11


def test_the_twelve_month_policy_and_the_registry_agree_for_sep_2577() -> None:
    """Not arithmetic we rely on -- a cross-check that the registry is consistent."""
    from sentinel.catalog.deprecations import earliest_removal

    for fid in ("roots", "sampling", "logging"):
        feature = FEATURES_BY_ID[fid]
        assert isinstance(feature.removal, FixedRevision)
        assert feature.removal.on_or_after == earliest_removal(feature.deprecated_on)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/harness/test_removal_windows.py -q`
Expected: FAIL — `ImportError: cannot import name 'FixedRevision'`

- [ ] **Step 3: Implement**

In `deprecations.py`, add the three window variants above `DeprecatedFeature`:

```python
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
    condition -- the number gets put in a plan and treated as a deadline.
    """

    description: str
    sep: str = ""

    def describe(self) -> str:
        return self.description


RemovalWindow = FixedRevision | FollowsFeature | AfterEvent
```

Change `DeprecatedFeature`: make `deprecated_on: date` required (no default, moved above the defaulted fields), add `removal: RemovalWindow`, and replace the `removable_on_or_after` property — which can no longer always answer — with nothing. Callers use `resolve_removal`.

```python
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
```

Rewrite `Inventory.months_remaining`:

```python
    def months_remaining(self, detection: Detection) -> int | None:
        """Whole months until the earliest removal, or None if it is not a date.

        Negative once the window has passed -- the feature may already have been
        removed, and reporting a negative number is more useful than clamping to
        zero and implying there is still time. `None` means the registry ties the
        window to an event rather than a date, and no number is honest.
        """
        window = resolve_removal(detection.feature)
        if not isinstance(window, FixedRevision):
            return None
        removal = window.on_or_after
        return (removal.year - self.as_of.year) * 12 + (removal.month - self.as_of.month)
```

Rewrite the six `FEATURES` entries to carry their real dates and windows. Keep every `name`, `replacement`, `citation` and `note` exactly as they are; change only `sep`, `deprecated_on` and `removal`:

```python
_SEP_2577 = FixedRevision(date(2027, 7, 28))

FEATURES: list[DeprecatedFeature] = [
    DeprecatedFeature(id="roots", ..., sep="SEP-2577",
                      deprecated_on=date(2026, 7, 28), removal=_SEP_2577),
    DeprecatedFeature(id="sampling", ..., sep="SEP-2577",
                      deprecated_on=date(2026, 7, 28), removal=_SEP_2577),
    DeprecatedFeature(id="logging", ..., sep="SEP-2577",
                      deprecated_on=date(2026, 7, 28), removal=_SEP_2577),
    DeprecatedFeature(id="http-sse", ..., sep="SEP-2596",
                      deprecated_on=date(2025, 3, 26),
                      removal=AfterEvent(
                          "three months after SEP-2596 reaches Final", sep="SEP-2596")),
    DeprecatedFeature(id="oauth-dcr", ..., sep="PR #2858",
                      deprecated_on=date(2026, 7, 28), removal=_SEP_2577),
    DeprecatedFeature(id="include-context", ..., sep="SEP-2596",
                      deprecated_on=date(2025, 11, 25),
                      removal=FollowsFeature(feature_id="sampling", sep="SEP-2577")),
]
```

Update `render_text` and `render_json` to use `resolve_removal` and to branch on the window type. Text:

```python
        window = resolve_removal(detection.feature)
        if isinstance(window, FixedRevision):
            months = inventory.months_remaining(detection)
            when = (
                f"removable on or after {window.on_or_after.isoformat()} "
                f"({months} month(s) from now)"
            )
        else:
            when = f"removable {window.describe()} (not yet scheduled)"
```

JSON: emit `"removal": {"kind": "fixed_revision", "onOrAfter": "...", "monthsRemaining": n}` or `{"kind": "after_event", "condition": "...", "sep": "...", "monthsRemaining": null}`, and `"deprecatedOn"` per feature.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/harness -m unit -q && uv run mypy --strict harness/src/sentinel`
Expected: PASS. Update any assertion in `tests/harness/test_deprecations.py` that hard-codes `2026-07-28` for `http-sse` or `include-context` — those assertions were asserting the bug.

- [ ] **Step 5: Commit**

```bash
git add harness/src/sentinel/catalog/deprecations.py tests/harness/data tests/harness/test_removal_windows.py tests/harness/test_deprecations.py
git commit -m "fix: the deprecation inventory reported two wrong dates and one impossible one

The registry says includeContext was deprecated 2025-11-25 and HTTP+SSE
2025-03-26; the inventory stamped all six 2026-07-28. Worse, two removal
windows are not date arithmetic at all -- includeContext's follows Sampling's,
and HTTP+SSE's is three months after SEP-2596 reaches Final, an event that has
not happened. The window is now one of three variants, and the event-relative
one prints its condition and declines to invent a date."
```

---

### Task 7: Reconcile the fixtures, the oracle and the docs

**Files:**
- Modify: `fixtures/server/nonconformant.py`
- Modify: `fixtures/server/conformant.py`
- Modify: `tests/harness/test_fixture_oracle.py` (only if its assertions encode counts)
- Modify: `README.md`
- Modify: `docs/HANDOFF.md` (§8.8 note on the lifecycle)

- [ ] **Step 1: Run the oracle to see what moved**

Run: `uv run pytest tests/harness/test_fixture_oracle.py -q -v`
Expected: the seeded-violation reconciliation test fails, because `SEEDED_VIOLATIONS` still names the three deprecated rule IDs and does not name their successors.

- [ ] **Step 2: Update the fixture's seeded violations**

In `fixtures/server/nonconformant.py`, in `SEEDED_VIOLATIONS`, replace:
- `MCP/2026-07-28/MUST/server-info-echoed` → `MCP/2026-07-28/SHOULD/server-info-echoed`
- `MCP/2026-07-28/MUST/tools-list-is-deterministic` → `MCP/2026-07-28/SHOULD/tools-list-is-deterministic`
- and add `MCP/2026-07-28/MUST/tools-list-connection-independent`

and update the corresponding `# VIOLATES:` source tags so the test that asserts the list matches the tags still passes. The fixture already serves a non-deterministic `tools/list`; make it *also* vary by connection by keying the shuffle on a per-connection counter, so the new MUST has something to catch:

```python
    # VIOLATES: MCP/2026-07-28/MUST/tools-list-connection-independent
    # Each connection gets its own tool set. This is exactly the
    # connection-shaped state the 2026-07-28 revision removed, and it is
    # invisible to any check that reuses one connection.
```

If `SEEDED_VIOLATIONS` counts MUST rules only, note that two entries are now SHOULD; adjust the oracle test to compute recall per severity rather than assuming all seeded rules are MUST. Do **not** drop the two SHOULD seeds — recall against them is still meaningful.

- [ ] **Step 3: Run the oracle**

Run: `uv run pytest tests/harness -m unit -q`
Expected: PASS, with MUST recall still 100%.

- [ ] **Step 4: Update the documentation**

In `README.md`, the two-scan example counts change; regenerate them by running the scans rather than editing by hand:

```bash
make up
uv run sentinel scan --endpoint http://localhost:9000/mcp --gate must ; echo "exit $?"
uv run sentinel scan --endpoint http://localhost:8080/mcp --gate must ; echo "exit $?"
```

Paste the real output. Add a short "Rule lifecycle" paragraph after the limitations section explaining that IDs are permanent, that three rules were corrected in 0.2.0, and that `--include-deprecated-rules` reproduces an older report.

In `docs/HANDOFF.md` §8.8, append a paragraph recording that the lifecycle mechanism now exists and naming the three corrections, so the handoff and the code do not disagree.

- [ ] **Step 5: Commit and open the PR**

```bash
make check
git add -A
git commit -m "docs: record the rule lifecycle and the three corrections

fixtures: seed a per-connection tools/list so the new MUST has something to catch"
git push -u origin feat/wp-14-rule-lifecycle
gh pr create --fill
```

---

# WP-15 — Error codes leave the sub-range the specification retired

**Branch:** `feat/wp-15-error-code-allocation`

Implements spec §3.1.

**The quote this work package exists for:**

> **`-32000` to `-32019` — legacy.** Codes in this sub-range were allocated by implementations before this policy was introduced. New codes **MUST NOT** be allocated in this sub-range, and new implementations **SHOULD NOT** use codes from this sub-range at all.
>
> New error codes for purposes not defined by this specification **SHOULD** be allocated outside the JSON-RPC reserved range (`-32768` to `-32000`); the remainder of the integer space is available for application-defined errors.

Broker is a new implementation written in 2026. `CLAUDE.md` and `HANDOFF.md` §7.2 both mandate the sub-range it should not use. They are wrong; the spec wins.

---

### Task 8: Move the eight codes and prove nothing is left behind

**Files:**
- Modify: `broker/internal/envelope/errors.go`
- Modify: `broker/internal/envelope/errors_test.go`
- Modify: `broker/internal/mrtr/engine.go` (three code references in the state-machine comment)
- Modify: `broker/internal/audit/chain_test.go:93`
- Test: `broker/internal/envelope/errors_test.go`

**Interfaces:**
- Consumes: nothing
- Produces:
  - Constants `CodeHandleNotResolvable = 1000`, `CodeMRTRFlowExpired = 1001`, `CodeMRTRArgumentsMutated = 1003`, `CodeMRTRStateInvalid = 1004`, `CodeMRTRResultNoLongerAvailable = 1005`, `CodeTokenBudgetExceeded = 1006`, `CodeScopeDenied = 1007`, `CodeAuditWriteFailed = 1008`
  - `func IsJSONRPCReserved(code int) bool` — `code <= -32000 && code >= -32768`
  - `func IsLegacySubRange(code int) bool` — `code <= -32000 && code >= -32019`
  - `func LegacyCode(code int) (int, bool)` — the pre-migration code, for the transition
  - `func WithLegacyCode(err *RPCError) *RPCError`

- [ ] **Step 1: Write the failing test**

Replace `TestImplementationCodes`-style range assertions in `broker/internal/envelope/errors_test.go` and add:

```go
// TestNoCodeInJSONRPCReservedRange. The specification says new codes SHOULD be
// allocated outside -32768…-32000 entirely. The three codes the spec itself
// defines are the only ones of ours inside it, and they are not ours.
func TestNoCodeInJSONRPCReservedRange(t *testing.T) {
	specDefined := map[int]bool{
		CodeHeaderMismatch:                  true,
		CodeMissingRequiredClientCapability: true,
		CodeUnsupportedProtocolVersion:      true,
		CodeParseError:                      true,
		CodeInvalidRequest:                  true,
		CodeMethodNotFound:                  true,
		CodeInvalidParams:                   true,
		CodeInternalError:                   true,
	}
	for _, code := range AllCodes() {
		if specDefined[code] {
			continue
		}
		if IsJSONRPCReserved(code) {
			t.Errorf("code %d is inside the JSON-RPC reserved range -32768…-32000; "+
				"new codes belong outside it", code)
		}
	}
}

// TestNoCodeInLegacySubRange. -32000…-32019 is the sub-range the revision
// retired: "new implementations SHOULD NOT use codes from this sub-range at all".
func TestNoCodeInLegacySubRange(t *testing.T) {
	for _, code := range AllCodes() {
		if IsLegacySubRange(code) {
			t.Errorf("code %d is in the retired legacy sub-range -32000…-32019", code)
		}
	}
}

func TestImplementationCodesArePositive(t *testing.T) {
	for _, code := range ImplementationCodes() {
		if code < 1000 || code > 1019 {
			t.Errorf("implementation code %d is outside the allocated block 1000…1019", code)
		}
	}
}

// TestLegacyCodeMapsEveryMigratedCode. A client mid-migration triages on the old
// number; every code we moved must be able to say what it used to be.
func TestLegacyCodeMapsEveryMigratedCode(t *testing.T) {
	for _, code := range ImplementationCodes() {
		old, ok := LegacyCode(code)
		if !ok {
			t.Errorf("code %d has no recorded legacy predecessor", code)
			continue
		}
		if !IsLegacySubRange(old) {
			t.Errorf("legacy predecessor %d of %d is not in -32000…-32019", old, code)
		}
	}
}

// TestOneThousandTwoIsDeliberatelyUnallocated mirrors the old
// TestMinus32002IsDeliberatelyUnallocated: 1002 is skipped because -32002 was,
// and keeping the ordinal gap keeps triage knowledge transferable.
func TestOneThousandTwoIsDeliberatelyUnallocated(t *testing.T) {
	for _, code := range AllCodes() {
		if code == 1002 {
			t.Fatal("1002 must stay unallocated: it mirrors -32002, which was " +
				"resource-not-found before this revision")
		}
	}
}

func TestWithLegacyCodeAttachesTheOldNumber(t *testing.T) {
	err := WithLegacyCode(New(CodeHandleNotResolvable, "nope", nil))
	data, ok := err.Data.(map[string]any)
	if !ok {
		t.Fatalf("Data = %#v, want a map carrying legacyCode", err.Data)
	}
	if data["legacyCode"] != -32000 {
		t.Errorf("legacyCode = %v, want -32000", data["legacyCode"])
	}
	if err.Code != CodeHandleNotResolvable {
		t.Errorf("Code = %d, want %d; the primary code must not change", err.Code, CodeHandleNotResolvable)
	}
}

func TestWithLegacyCodePreservesExistingData(t *testing.T) {
	err := WithLegacyCode(New(CodeScopeDenied, "denied", map[string]any{"scope": "ops.write"}))
	data := err.Data.(map[string]any)
	if data["scope"] != "ops.write" {
		t.Errorf("existing data was dropped: %#v", data)
	}
	if data["legacyCode"] != -32007 {
		t.Errorf("legacyCode = %v, want -32007", data["legacyCode"])
	}
}

func TestWithLegacyCodeIgnoresCodesThatNeverMoved(t *testing.T) {
	err := WithLegacyCode(New(CodeInvalidParams, "bad", nil))
	if err.Data != nil {
		t.Errorf("Data = %#v, want nil; -32602 never moved", err.Data)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `export PATH="/opt/homebrew/bin:$PATH" && cd broker && go test ./internal/envelope/ -run 'Legacy|Reserved|Positive|OneThousand' -v`
Expected: FAIL — undefined: `IsJSONRPCReserved`, `IsLegacySubRange`, `LegacyCode`, `WithLegacyCode`.

- [ ] **Step 3: Implement**

In `errors.go`, replace the header comment's allocation table and the implementation-code block:

```go
// The 2026-07-28 allocation policy partitions the JSON-RPC server-error range:
//
//	-32000 … -32019   LEGACY. Allocated by implementations before the policy
//	                  existed. "New codes MUST NOT be allocated in this
//	                  sub-range, and new implementations SHOULD NOT use codes
//	                  from this sub-range at all."
//	-32020 … -32099   reserved for the specification — never allocate here
//
// And: "New error codes for purposes not defined by this specification SHOULD
// be allocated outside the JSON-RPC reserved range (-32768 to -32000)."
//
// Sentinel is a new implementation, so its own codes live at 1000…1019 —
// outside the reserved range entirely. They were at -32000…-32019 through
// v0.1.0, which this revision retired; LegacyCode maps each new code back to
// the one it replaced, and WithLegacyCode attaches it for the transition.

// Sentinel's own codes, outside the JSON-RPC reserved range.
//
// The low ordinal is preserved from the pre-migration code so triage knowledge
// transfers: -32007 became 1007. 1002 is skipped for the same reason -32002
// was — it was resource-not-found before this revision, and reusing the ordinal
// makes triage ambiguous for exactly the clients most likely to be mid-migration.
const (
	CodeHandleNotResolvable         = 1000
	CodeMRTRFlowExpired             = 1001
	CodeMRTRArgumentsMutated        = 1003
	CodeMRTRStateInvalid            = 1004
	CodeMRTRResultNoLongerAvailable = 1005
	CodeTokenBudgetExceeded         = 1006
	CodeScopeDenied                 = 1007
	CodeAuditWriteFailed            = 1008
)

// legacyCodes maps each migrated code to the code it carried through v0.1.0.
//
// maps error codes to their predecessors and contains no secret.
//
//nolint:gosec // G101 pattern-matches the identifier as a credential table
var legacyCodes = map[int]int{
	CodeHandleNotResolvable:         -32000,
	CodeMRTRFlowExpired:             -32001,
	CodeMRTRArgumentsMutated:        -32003,
	CodeMRTRStateInvalid:            -32004,
	CodeMRTRResultNoLongerAvailable: -32005,
	CodeTokenBudgetExceeded:         -32006,
	CodeScopeDenied:                 -32007,
	CodeAuditWriteFailed:            -32008,
}

// LegacyCode returns the code this one replaced, if it replaced one.
func LegacyCode(code int) (int, bool) {
	old, ok := legacyCodes[code]
	return old, ok
}

// WithLegacyCode attaches data.legacyCode so a client mid-migration can triage
// on either number. Scheduled for removal — see BROKER_EMIT_LEGACY_ERROR_CODE.
func WithLegacyCode(err *RPCError) *RPCError {
	old, ok := LegacyCode(err.Code)
	if !ok {
		return err
	}
	data := map[string]any{}
	if existing, isMap := err.Data.(map[string]any); isMap {
		for k, v := range existing {
			data[k] = v
		}
	} else if err.Data != nil {
		data["detail"] = err.Data
	}
	data["legacyCode"] = old
	return &RPCError{Code: err.Code, Message: err.Message, Data: data}
}

// IsJSONRPCReserved reports whether code is inside JSON-RPC's reserved range.
func IsJSONRPCReserved(code int) bool { return code <= -32000 && code >= -32768 }

// IsLegacySubRange reports whether code is in the sub-range this revision retired.
func IsLegacySubRange(code int) bool { return code <= -32000 && code >= -32019 }
```

Keep `IsSpecReserved` unchanged. Update the comment references in `broker/internal/mrtr/engine.go` (`-32004` → `1004`, `-32003` → `1003`, `-32000` → `1000`) and the sample value in `broker/internal/audit/chain_test.go:93` (`-32000` → `1000`).

- [ ] **Step 4: Run the whole Go suite**

Run: `export PATH="/opt/homebrew/bin:$PATH" && cd broker && go build ./... && go test ./... -race`
Expected: PASS. Every call site uses the named constant, so nothing but the numbers moved.

- [ ] **Step 5: Commit**

```bash
git checkout -b feat/wp-15-error-code-allocation
git add broker/internal/envelope broker/internal/mrtr/engine.go broker/internal/audit/chain_test.go
git commit -m "fix: our error codes were in the sub-range this revision retired

'-32000 to -32019 -- legacy. New codes MUST NOT be allocated in this sub-range,
and new implementations SHOULD NOT use codes from this sub-range at all.'
Broker is a new implementation. CLAUDE.md and HANDOFF 7.2 both mandated the
sub-range; both are wrong and the spec wins.

The eight codes move to 1000..1019, keeping the low ordinal so triage knowledge
transfers. 1002 stays skipped, mirroring -32002."
```

---

### Task 9: Emit `data.legacyCode` through the transition, behind a config key

**Files:**
- Modify: `broker/internal/config/config.go`
- Modify: `broker/internal/transport/http.go` (`writeError`, line ~225)
- Modify: `broker/internal/transport/stdio.go` (its error path)
- Modify: `broker/internal/config/config_test.go`
- Test: `broker/internal/transport/http_test.go`

**Interfaces:**
- Consumes: `envelope.WithLegacyCode` from Task 8
- Produces:
  - `Config.EmitLegacyErrorCode bool` — env `BROKER_EMIT_LEGACY_ERROR_CODE`, default `true`
  - `transport.WithLegacyErrorCodes(bool) Option`

- [ ] **Step 1: Write the failing test**

Add to `broker/internal/transport/http_test.go`:

```go
// TestErrorCarriesLegacyCodeDuringTransition. A client that triaged on -32007
// through v0.1.0 must be able to keep doing so for one release.
func TestErrorCarriesLegacyCodeDuringTransition(t *testing.T) {
	// Build the server the same way the other tests in this file do, with
	// WithLegacyErrorCodes(true), then provoke a scope denial.
	// Assert: error.code == 1007 and error.data.legacyCode == -32007.
}

func TestLegacyCodeIsOmittedWhenDisabled(t *testing.T) {
	// Same, with WithLegacyErrorCodes(false).
	// Assert: error.code == 1007 and error.data has no legacyCode key.
}
```

Fill both in following the construction pattern already used by the neighbouring tests in that file — read the top of `http_test.go` for how a `Server` is assembled and how a response is decoded.

Add to `broker/internal/config/config_test.go` a case asserting `Default().EmitLegacyErrorCode == true` and that `BROKER_EMIT_LEGACY_ERROR_CODE=false` parses to `false`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `export PATH="/opt/homebrew/bin:$PATH" && cd broker && go test ./internal/transport/ ./internal/config/ -run 'Legacy' -v`
Expected: FAIL — undefined: `WithLegacyErrorCodes`, `EmitLegacyErrorCode`.

- [ ] **Step 3: Implement**

`config.go`: add the field with a comment stating it is scheduled for removal, `Default()` sets `true`, `FromEnv()` parses it with `strconv.ParseBool` exactly as `AllowLegacyUnversioned` is parsed.

`transport/http.go`: add the option and the server field —

```go
// WithLegacyErrorCodes attaches data.legacyCode to errors whose code moved out
// of -32000…-32019 in v0.2.0, so a client mid-migration can triage on either.
// Scheduled for removal.
func WithLegacyErrorCodes(on bool) Option {
	return func(s *Server) { s.legacyErrorCodes = on }
}
```

and in `writeError`, wrap once, at the single serialization point:

```go
func (s *Server) writeError(w http.ResponseWriter, id json.RawMessage, rpcErr *envelope.RPCError) {
	if s.legacyErrorCodes {
		rpcErr = envelope.WithLegacyCode(rpcErr)
	}
	// ... unchanged
}
```

Do the same at `stdio.go`'s error path. Wire the option from `main.go` where the other options are passed: `transport.WithLegacyErrorCodes(cfg.EmitLegacyErrorCode)`.

- [ ] **Step 4: Run tests**

Run: `export PATH="/opt/homebrew/bin:$PATH" && cd broker && go test ./... -race && golangci-lint run`
Expected: PASS, no lint findings.

- [ ] **Step 5: Commit**

```bash
git add broker
git commit -m "feat: data.legacyCode through the transition, behind BROKER_EMIT_LEGACY_ERROR_CODE"
```

---

### Task 10: A rule that detects the mistake we just fixed, and the docs that mandated it

**Files:**
- Create: `harness/src/sentinel/catalog/should/errors.py`
- Modify: `harness/src/sentinel/catalog/should/__init__.py`
- Modify: `fixtures/server/nonconformant.py`
- Modify: `CLAUDE.md`
- Modify: `docs/HANDOFF.md` (§7.2 table, §14 gotcha 14)
- Modify: `docs/MIGRATION.md` (the allocation table)
- Modify: `docs/demo/README.md` (the sample error body)
- Test: `tests/harness/test_catalog.py`

**Interfaces:**
- Consumes: the lifecycle from WP-14 Task 1
- Produces: live rule `MCP/2026-07-28/SHOULD/no-errors-in-legacy-range`

- [ ] **Step 1: Write the failing test**

Append to `tests/harness/test_catalog.py`:

```python
def test_legacy_range_rule_fires_on_the_nonconformant_fixture(
    nonconformant_endpoint: str,
) -> None:
    from sentinel.catalog.base import REGISTRY, Outcome
    from sentinel.probe.client import Probe

    rule = {r.id: r for r in REGISTRY.all()}["MCP/2026-07-28/SHOULD/no-errors-in-legacy-range"]
    with Probe(nonconformant_endpoint) as probe:
        assert rule.evaluate(probe).outcome is Outcome.FAIL


def test_legacy_range_rule_passes_the_conformant_fixture(conformant_endpoint: str) -> None:
    from sentinel.catalog.base import REGISTRY, Outcome
    from sentinel.probe.client import Probe

    rule = {r.id: r for r in REGISTRY.all()}["MCP/2026-07-28/SHOULD/no-errors-in-legacy-range"]
    with Probe(conformant_endpoint) as probe:
        assert rule.evaluate(probe).outcome in (Outcome.PASS, Outcome.NOT_APPLICABLE)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/harness/test_catalog.py -q -k legacy_range`
Expected: FAIL — `KeyError`.

- [ ] **Step 3: Implement the rule**

Create `harness/src/sentinel/catalog/should/errors.py`:

```python
"""SHOULD rules for error-code allocation."""

from __future__ import annotations

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe

#: -32002 is excluded deliberately. It is in the legacy sub-range, but a server
#: emitting it for resource-not-found is already caught by
#: MCP/2026-07-28/MUST/resource-not-found-is-invalid-params, and reporting one
#: defect twice makes a report harder to act on, not more thorough.
_EXCLUDED = {-32002}


@rule(
    id="MCP/2026-07-28/SHOULD/no-errors-in-legacy-range",
    title="No error code comes from the retired -32000…-32019 sub-range",
    severity=Severity.SHOULD,
    citation=f"{SPEC_BASE}/basic/index#error-codes",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Move implementation-defined codes outside the JSON-RPC reserved range "
        "(-32768 to -32000) entirely. The revision retired -32000…-32019: 'new "
        "implementations SHOULD NOT use codes from this sub-range at all', and apart "
        "from -32002 'receivers MUST NOT assume any specific meaning for these codes' "
        "-- so a code you emit there is a code no client can interpret."
    ),
    introduced_in="0.2.0",
)
def no_errors_in_legacy_range(probe: Probe) -> RuleResult:
    provocations: list[tuple[str, object]] = [
        ("an unknown method", probe.call("sentinel/definitely-not-a-real-method")),
        ("an unknown tool", probe.tools_call("sentinel-no-such-tool", {})),
        ("an unknown resource", probe.resources_read("sentinel://no/such/resource")),
        ("tools/call with no name", probe.call("tools/call", {})),
        ("a missing Mcp-Method header", probe.tools_list(omit_mcp_method=True)),
    ]

    offenders: list[str] = []
    observed = 0
    for label, response in provocations:
        error = response.error()  # type: ignore[attr-defined]
        if not isinstance(error, dict):
            continue
        code = error.get("code")
        if not isinstance(code, int):
            continue
        observed += 1
        if code in _EXCLUDED:
            continue
        if -32019 <= code <= -32000:
            offenders.append(f"{label} returned {code}")

    if observed == 0:
        return RuleResult.indeterminate("no provocation produced an error to inspect")
    if offenders:
        return RuleResult.failed(
            f"{len(offenders)} of {observed} errors came from the retired "
            f"-32000…-32019 sub-range: {offenders}",
            evidence="; ".join(offenders),
        )
    return RuleResult.passed(
        f"none of {observed} provoked errors used the retired sub-range"
    )
```

> `response.error()` must exist on `RawResponse`. Check `harness/src/sentinel/probe/transport.py`; if the accessor is named differently (e.g. `envelope()["error"]`), use whatever `must/headers.py` already uses to read an error code and match it exactly — that file provokes errors the same way.

Add `errors` to `should/__init__.py`.

- [ ] **Step 4: Seed the fixture violation**

In `fixtures/server/nonconformant.py`, make one error path return a code in the retired sub-range (`-32011` is a good choice — clearly ours, clearly not `-32002`), tag it, and add the rule id to `SEEDED_VIOLATIONS`:

```python
    # VIOLATES: MCP/2026-07-28/SHOULD/no-errors-in-legacy-range
    # -32011 is inside -32000..-32019, which the revision retired: apart from
    # -32002, "receivers MUST NOT assume any specific meaning for these codes".
```

Verify `fixtures/server/conformant.py` emits nothing in the range.

- [ ] **Step 5: Fix the documents that mandated the wrong range**

- `CLAUDE.md`, "Hard constraints": replace *"Error codes `-32020`…`-32099` are reserved for the spec. Ours live in `-32000`…`-32019`."* with: *"Error codes `-32020`…`-32099` are reserved for the spec and `-32000`…`-32019` is the sub-range it retired. Ours live at `1000`…`1019`, outside the JSON-RPC reserved range entirely."*
- `docs/HANDOFF.md` §7.2 table row and §14 gotcha 14: same correction, with a note that this is a recorded divergence from the handoff as written and the reason (the spec's allocation policy).
- `docs/MIGRATION.md` allocation table: `-32000 … -32019` is no longer "you"; add a row for the retirement and a short paragraph on what to do about codes already allocated there.
- `docs/demo/README.md:95`: `-32000` → `1000`.

- [ ] **Step 6: Run everything and open the PR**

```bash
export PATH="/opt/homebrew/bin:$PATH"
make check
make up && make demo && make down
git add -A
git commit -m "feat: a rule for the legacy sub-range, and the docs that mandated it

CLAUDE.md and HANDOFF 7.2 told an implementer to allocate in -32000..-32019.
Both are corrected here, because a repository that ships a scanner cannot also
ship instructions to violate the spec it scans for."
git push -u origin feat/wp-15-error-code-allocation
gh pr create --fill
```

---

# WP-16 — The HTTP layer: request metadata and status codes

**Branch:** `feat/wp-16-http-layer`

Implements spec §6.1 and §6.2. Ten new rules. Every quote below is from `basic/transports/streamable-http` unless marked otherwise.

**Before writing anything, read this.** The existing `mcp-name-header-required` rule may be a false positive. The spec's Standard Request Headers table says `Mcp-Method` is required for *"All requests"* but `Mcp-Name` only for *"`tools/call`, `resources/read`, `prompts/get` requests"*. If that rule omits `Mcp-Name` from a `tools/list` request, it is demanding a header the spec does not require there. Task 11 audits it.

---

### Task 11: Audit `Mcp-Name`, and add TLS, proxy and retry options

**Files:**
- Modify: `harness/src/sentinel/catalog/must/headers.py`
- Modify: `harness/src/sentinel/probe/transport.py`
- Modify: `harness/src/sentinel/probe/client.py`
- Modify: `harness/src/sentinel/cli.py`
- Test: `tests/harness/test_probe_meta.py` (extend)

**Interfaces:**
- Consumes: `Probe.build` overrides from WP-14 Task 3
- Produces:
  - `Transport(endpoint, *, timeout, bearer_token, verify: bool | str = True, proxy: str | None = None, client_cert: str | tuple[str, str] | None = None, retries: int = 2)`
  - `Probe(..., verify=True, proxy=None, client_cert=None, retries=2)`, propagated by `new_connection()`
  - `Probe.notify(method, params=None, **overrides) -> RawResponse` — an `id`-less POST
  - `Probe.prompts_get(name, arguments=None, **overrides) -> RawResponse`
  - CLI options `--insecure`, `--ca-bundle`, `--proxy`, `--client-cert`, `--retries`

- [ ] **Step 1: Audit the `Mcp-Name` rule**

Run: `uv run sentinel catalog list | grep -A2 mcp-name` and read `harness/src/sentinel/catalog/must/headers.py`.

If `mcp_name_required` omits `Mcp-Name` from a method that is **not** `tools/call`, `resources/read` or `prompts/get`, it is demanding a header the spec does not require. Change it to provoke on `tools/call` instead:

```python
    name = probe.first_tool_name() or "sentinel-no-such-tool"
    response = probe.tools_call(name, {}, omit_mcp_name=True)
```

and record the reason in a comment:

```python
    # Mcp-Name is required for tools/call, resources/read and prompts/get -- not
    # for "All requests", which is Mcp-Method's row in the table. Provoking on
    # tools/list would demand a header the specification does not require there.
```

This is a behaviour change to a live rule that does not change its *meaning* (it still tests "Mcp-Name is required where required"), so it keeps its id. Note it in the commit message.

- [ ] **Step 2: Write the failing test**

Append to `tests/harness/test_probe_meta.py`:

```python
def test_a_notification_has_no_id() -> None:
    with Probe("http://unused.invalid/mcp") as probe:
        request = probe.build_notification("notifications/does-not-exist")
    body = json.loads(request.body())
    assert "id" not in body
    assert body["jsonrpc"] == "2.0"


def test_transport_options_propagate_to_a_new_connection() -> None:
    with Probe("http://unused.invalid/mcp", verify=False, proxy="http://p:1", retries=5) as a:
        b = a.new_connection()
        try:
            assert b._transport.verify is False
            assert b._transport.proxy == "http://p:1"
            assert b._transport.retries == 5
        finally:
            b.close()


def test_a_transport_error_is_retried_but_a_served_response_is_not(monkeypatch) -> None:
    """Retry transport failures only.

    Retrying a response the server actually sent would re-run side effects and
    corrupt every idempotency-sensitive rule in the catalog.
    """
    import httpx

    from sentinel.probe.transport import Request, Transport

    calls = {"n": 0}

    def flaky(*args: object, **kwargs: object) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ConnectError("boom")
        return httpx.Response(500, json={"jsonrpc": "2.0", "id": "1", "error": {"code": -1}})

    transport = Transport("http://unused.invalid/mcp", retries=2)
    monkeypatch.setattr(transport._client, "post", flaky)
    response = transport.send(Request(method="tools/list", params=None, request_id="1", headers={}))

    assert calls["n"] == 3          # two retries, then success
    assert response.status == 500   # and the 500 is NOT retried
```

- [ ] **Step 3: Implement**

`transport.py`: store `verify`, `proxy`, `client_cert`, `retries`; pass `verify`/`proxy`/`cert` to `httpx.Client`; wrap the `post` call in a bounded retry with exponential backoff that catches **only** `httpx.RequestError`:

```python
        started = time.perf_counter()
        last_error: str | None = None
        for attempt in range(self.retries + 1):
            try:
                resp = self._client.post(self.endpoint, content=request.body(), headers=headers)
            except httpx.RequestError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < self.retries:
                    # Transport failures only. A response the server actually
                    # sent is never retried: re-running a tools/call would
                    # re-run its side effects and make every idempotency rule
                    # in the catalog meaningless.
                    time.sleep(0.1 * (2**attempt))
                    continue
                return RawResponse(
                    status=0, headers={}, body=b"",
                    elapsed_s=time.perf_counter() - started,
                    transport_error=last_error,
                )
            return RawResponse(
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                body=resp.content,
                elapsed_s=time.perf_counter() - started,
            )
        raise AssertionError("unreachable")
```

`client.py`: thread the four options through `__init__` and `new_connection()`; add

```python
    def build_notification(
        self, method: str, params: dict[str, Any] | None = None, **overrides: Any
    ) -> Request:
        """A JSON-RPC notification: no id, and no response is expected."""
        request = self.build(method, params, **overrides)
        request.request_id = None
        return request

    def notify(self, method: str, params: dict[str, Any] | None = None, **overrides: Any) -> RawResponse:
        return self._transport.send(self.build_notification(method, params, **overrides))

    def prompts_get(
        self, name: str, arguments: dict[str, Any] | None = None, **overrides: Any
    ) -> RawResponse:
        return self.call("prompts/get", {"name": name, "arguments": arguments or {}}, **overrides)
```

`Request.request_id` must become `Any | None` and `Request.body()` must omit `"id"` when it is `None`. Add `"prompts/get": "name"` to `NAME_BEARING` — it is already there; verify.

`cli.py`: add `--insecure` (`verify=False`), `--ca-bundle PATH` (`verify=PATH`), `--proxy URL`, `--client-cert PATH`, `--retries N`, threading them through `run_scan` to `Probe`. `--insecure` must print a warning to stderr: scanning a server whose certificate you do not check is a scan you cannot attribute.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/harness -m unit -q && uv run mypy --strict harness/src/sentinel`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git checkout -b feat/wp-16-http-layer
git add harness/src/sentinel tests/harness/test_probe_meta.py
git commit -m "feat: TLS, proxy and bounded transport retry; notifications and prompts/get

Also narrows mcp-name-header-required to the three methods the header table
actually requires Mcp-Name for. It was provoking on a method where the spec
requires no such header, which is a false positive by the same definition
MEASUREMENTS.md uses."
```

---

### Task 12: `must/meta.py` — the required request metadata

**Files:**
- Create: `harness/src/sentinel/catalog/must/meta.py`
- Modify: `harness/src/sentinel/catalog/must/__init__.py`
- Test: `tests/harness/test_catalog.py` (extend with the fixture-oracle pattern already used there)

**Interfaces:**
- Consumes: `omit_client_capabilities`, `omit_protocol_version_header` overrides from WP-14 Task 3
- Produces: rules `missing-client-capabilities-rejected`, `missing-protocol-version-rejected`, `missing-capability-error-shape`

**Quotes:** *"A request missing any required field is malformed; the server **MUST** reject it with JSON-RPC error code `-32602` (Invalid params). On HTTP, the response status **MUST** be `400 Bad Request`."* And: *"the server **MUST** return a `MissingRequiredClientCapabilityError` (`-32021`) whose `data.requiredCapabilities` lists the missing capabilities. On HTTP, the response status **MUST** be `400 Bad Request`."*

- [ ] **Step 1: Write the failing test**

Add to `tests/harness/test_catalog.py`, following the existing per-rule fixture assertions:

```python
META_RULES = [
    "MCP/2026-07-28/MUST/missing-client-capabilities-rejected",
    "MCP/2026-07-28/MUST/missing-protocol-version-rejected",
]


@pytest.mark.parametrize("rule_id", META_RULES)
def test_meta_rules_pass_the_conformant_fixture(rule_id: str, conformant_endpoint: str) -> None:
    from sentinel.catalog.base import REGISTRY, Outcome
    from sentinel.probe.client import Probe

    rule = {r.id: r for r in REGISTRY.all()}[rule_id]
    with Probe(conformant_endpoint) as probe:
        assert rule.evaluate(probe).outcome is Outcome.PASS, rule_id


@pytest.mark.parametrize("rule_id", META_RULES)
def test_meta_rules_fail_the_nonconformant_fixture(rule_id: str, nonconformant_endpoint: str) -> None:
    from sentinel.catalog.base import REGISTRY, Outcome
    from sentinel.probe.client import Probe

    rule = {r.id: r for r in REGISTRY.all()}[rule_id]
    with Probe(nonconformant_endpoint) as probe:
        assert rule.evaluate(probe).outcome is Outcome.FAIL, rule_id
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/harness/test_catalog.py -q -k meta_rules`
Expected: FAIL — `KeyError`.

- [ ] **Step 3: Implement**

Create `harness/src/sentinel/catalog/must/meta.py`:

```python
"""MUST rules for the per-request `_meta` protocol fields.

The revision removed the handshake, so every request carries its own protocol
version and client capabilities. A server that accepts a request without them is
inferring them from somewhere -- and the only somewhere left is the connection,
which is the state this revision removed.
"""

from __future__ import annotations

from typing import Any

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe
from sentinel.probe.transport import RawResponse

BASIC = f"{SPEC_BASE}/basic/index"


def _rejected_as_invalid_params(response: RawResponse, what: str) -> RuleResult:
    """The shared verdict: -32602 AND HTTP 400, both required."""
    if not response.reached_server:
        return RuleResult.indeterminate(
            f"the target was unreachable while testing {what}: {response.transport_error}"
        )
    code = response.error_code()
    if code is None:
        return RuleResult.failed(
            f"a request omitting {what} was SERVED; a required field was inferred "
            "rather than read, and the only place left to infer it from is the connection",
            evidence=f"HTTP {response.status}, no JSON-RPC error in the body",
        )
    problems: list[str] = []
    if code != -32602:
        problems.append(f"error code was {code}, not -32602")
    if response.status != 400:
        problems.append(f"HTTP status was {response.status}, not 400")
    if problems:
        return RuleResult.failed(
            f"a request omitting {what} was rejected, but not as the spec requires: "
            + "; ".join(problems),
            evidence=f"HTTP {response.status}, code {code}",
        )
    return RuleResult.passed(f"a request omitting {what} was rejected with -32602 and HTTP 400")


@rule(
    id="MCP/2026-07-28/MUST/missing-client-capabilities-rejected",
    title="A request without clientCapabilities is rejected with -32602 and HTTP 400",
    severity=Severity.MUST,
    citation=f"{BASIC}#meta",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Reject a request whose _meta omits io.modelcontextprotocol/clientCapabilities "
        "with -32602 and HTTP 400. The field is Required: Yes, and a server that "
        "proceeds without it is guessing what the client can do -- which is how a "
        "server ends up returning an elicitation request to a client that cannot "
        "elicit, stalling the call forever."
    ),
    introduced_in="0.2.0",
)
def missing_client_capabilities_rejected(probe: Probe) -> RuleResult:
    return _rejected_as_invalid_params(
        probe.tools_list(omit_client_capabilities=True),
        "io.modelcontextprotocol/clientCapabilities",
    )


@rule(
    id="MCP/2026-07-28/MUST/missing-protocol-version-rejected",
    title="A request without a declared protocol version is rejected with -32602 and HTTP 400",
    severity=Severity.MUST,
    citation=f"{BASIC}#meta",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Reject a request whose _meta omits io.modelcontextprotocol/protocolVersion with "
        "-32602 and HTTP 400. Serving it means the version came from somewhere other than "
        "the request, and in a protocol with no handshake there is nowhere else it can "
        "legitimately come from."
    ),
    introduced_in="0.2.0",
)
def missing_protocol_version_rejected(probe: Probe) -> RuleResult:
    # version=None omits the body field; the header is omitted with it, because
    # sending a header with nothing in the body to agree with would provoke a
    # HeaderMismatch instead and test the wrong rule.
    return _rejected_as_invalid_params(
        probe.tools_list(version=None, omit_protocol_version_header=True),
        "io.modelcontextprotocol/protocolVersion",
    )


@rule(
    id="MCP/2026-07-28/MUST/missing-capability-error-shape",
    title="A -32021 error names the capabilities it needed",
    severity=Severity.MUST,
    citation=f"{BASIC}#meta",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "When returning -32021 MissingRequiredClientCapability, populate "
        "data.requiredCapabilities with the capabilities the request needed and HTTP "
        "400. Without the list the client cannot know what to declare, so the error "
        "tells it that it failed but not how to succeed."
    ),
    introduced_in="0.2.0",
)
def missing_capability_error_shape(probe: Probe) -> RuleResult:
    # The probe declares no capabilities at all, so any operation that needs one
    # should provoke this. If nothing does, the rule does not apply -- it is not
    # a defect for a server to need no client capability.
    attempts: list[RawResponse] = [
        probe.tools_list(client_capabilities={}),
        probe.prompts_list(client_capabilities={}),
    ]
    name = probe.first_tool_name()
    if name is not None:
        attempts.append(probe.tools_call(name, {}, client_capabilities={}))

    for response in attempts:
        if response.error_code() != -32021:
            continue
        error = response.error() or {}
        data = error.get("data")
        required = data.get("requiredCapabilities") if isinstance(data, dict) else None
        problems: list[str] = []
        if not isinstance(required, list) or not required:
            problems.append(f"data.requiredCapabilities is {required!r}, not a non-empty array")
        if response.status != 400:
            problems.append(f"HTTP status was {response.status}, not 400")
        if problems:
            return RuleResult.failed(
                "a -32021 error was returned, but not in the shape the spec requires: "
                + "; ".join(problems),
                evidence=str(error)[:400],
            )
        return RuleResult.passed(
            f"-32021 named the capabilities it needed: {required}"
        )

    return RuleResult.not_applicable(
        "no request the probe can make required a client capability, so -32021 was "
        "never provoked"
    )
```

Add `meta` to `must/__init__.py`.

- [ ] **Step 4: Seed the fixtures**

`conformant.py`: reject a request whose `_meta` lacks either required field with `-32602` and HTTP 400.
`nonconformant.py`: serve both anyway, tagged:

```python
    # VIOLATES: MCP/2026-07-28/MUST/missing-client-capabilities-rejected
    # VIOLATES: MCP/2026-07-28/MUST/missing-protocol-version-rejected
```

and add both ids to `SEEDED_VIOLATIONS`.

- [ ] **Step 5: Run and commit**

```bash
uv run pytest tests/harness -m unit -q && uv run sentinel catalog validate
git add harness/src/sentinel/catalog fixtures tests
git commit -m "feat: rules for the required per-request _meta fields"
```

---

### Task 13: `must/http.py` — status codes, Origin, Content-Type, notifications

**Files:**
- Create: `harness/src/sentinel/catalog/must/http.py`
- Modify: `harness/src/sentinel/catalog/must/__init__.py`
- Modify: `harness/src/sentinel/catalog/must/headers.py` (tighten two existing rules)
- Test: `tests/harness/test_catalog.py`

**Interfaces:**
- Consumes: `Probe.notify`, `omit_protocol_version_header`, `protocol_version_header` from Task 11
- Produces: `unknown-method-http-404`, `protocol-version-header-required`, `protocol-version-header-body-mismatch-rejected`, `invalid-origin-rejected`, `response-content-type-valid`, `notification-not-answered-with-a-result`, and SHOULD `get-delete-405`

**Quotes, all verified:**
- *"If the server does not implement the requested RPC method, it **MUST** respond with `404 Not Found` and a JSON-RPC error with code `-32601`."*
- *"Every POST request to the MCP endpoint **MUST** include an `MCP-Protocol-Version` header… The header value **MUST** match the `io.modelcontextprotocol/protocolVersion` field carried in the request body's `_meta`. If the values do not match, the server **MUST** reject the request with `400 Bad Request` and a `HeaderMismatch` JSON-RPC error."*
- *"If the `Origin` header is present and invalid, servers **MUST** respond with HTTP 403 Forbidden."*
- *"If the body is a JSON-RPC request, the server **MUST** return either `Content-Type: application/json`… or `Content-Type: text/event-stream`."*
- *"If the body is a JSON-RPC notification: If the server accepts it, the server **MUST** return HTTP status code `202 Accepted` with no body. If the server cannot accept it, it **MUST** return an HTTP error status code."*
- *"HTTP GET or DELETE to the MCP endpoint: respond with `405 Method Not Allowed`."* (SHOULD)

- [ ] **Step 1: Write the failing test**

Extend `tests/harness/test_catalog.py` with the same parametrised pair used in Task 12, over:

```python
HTTP_RULES = [
    "MCP/2026-07-28/MUST/unknown-method-http-404",
    "MCP/2026-07-28/MUST/protocol-version-header-required",
    "MCP/2026-07-28/MUST/protocol-version-header-body-mismatch-rejected",
    "MCP/2026-07-28/MUST/invalid-origin-rejected",
    "MCP/2026-07-28/MUST/response-content-type-valid",
]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/harness/test_catalog.py -q -k http_rules`
Expected: FAIL — `KeyError`.

- [ ] **Step 3: Implement**

Create `harness/src/sentinel/catalog/must/http.py`. The three that need care:

```python
#: RFC 2606 reserves `.invalid` so that it can never resolve. No allowlist a
#: server could legitimately hold contains an origin under it, which is what
#: makes serving a request from here evidence of no validation rather than
#: evidence of a permissive policy.
FOREIGN_ORIGIN = "https://sentinel-rebinding-probe.invalid"


@rule(
    id="MCP/2026-07-28/MUST/invalid-origin-rejected",
    title="A request from an impossible Origin is refused with HTTP 403",
    severity=Severity.MUST,
    citation=f"{SPEC_BASE}/basic/transports/streamable-http#security-endpoint",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Validate the Origin header on every request and answer 403 Forbidden when it "
        "is present and not allowed. Without it a page the user visits can drive this "
        "server through the user's own browser -- which is the DNS rebinding attack the "
        "requirement exists for, and it does not care that the endpoint is internal."
    ),
    introduced_in="0.2.0",
)
def invalid_origin_rejected(probe: Probe) -> RuleResult:
    response = probe.tools_list(headers={"Origin": FOREIGN_ORIGIN})
    if not response.reached_server:
        return RuleResult.indeterminate(f"unreachable: {response.transport_error}")
    if response.status == 403:
        return RuleResult.passed(f"Origin {FOREIGN_ORIGIN} was refused with 403")
    if 200 <= response.status < 300:
        return RuleResult.failed(
            f"a request carrying Origin: {FOREIGN_ORIGIN} was SERVED (HTTP "
            f"{response.status}). .invalid can never resolve, so no allowlist "
            "contains it and no Origin check ran",
            evidence=f"HTTP {response.status}",
        )
    return RuleResult.indeterminate(
        f"the request was refused with HTTP {response.status} rather than 403; the "
        "refusal may be for another reason entirely, so this does not settle whether "
        "Origin is validated"
    )


@rule(
    id="MCP/2026-07-28/MUST/notification-not-answered-with-a-result",
    title="A notification is accepted with 202, or refused; never answered",
    severity=Severity.MUST,
    citation=f"{SPEC_BASE}/basic/transports/streamable-http#sending-messages",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Answer a JSON-RPC notification with 202 Accepted and an empty body, or with an "
        "HTTP error status if you cannot accept it. A notification carries no id, so a "
        "JSON-RPC result sent back cannot be correlated with anything and the client has "
        "no way to interpret it."
    ),
    introduced_in="0.2.0",
)
def notification_not_answered_with_a_result(probe: Probe) -> RuleResult:
    response = probe.notify("notifications/sentinel-probe")
    if not response.reached_server:
        return RuleResult.indeterminate(f"unreachable: {response.transport_error}")
    if response.status == 202:
        if response.body.strip():
            return RuleResult.failed(
                "202 Accepted carried a body; the spec says 'with no body'",
                evidence=response.body[:200].decode("utf-8", "replace"),
            )
        return RuleResult.passed("a notification was accepted with 202 and no body")
    if response.status >= 400:
        return RuleResult.passed(
            f"the notification was refused with HTTP {response.status}, which the spec "
            "permits for a notification the server cannot accept"
        )
    if response.result() is not None:
        return RuleResult.failed(
            f"a notification (no id) was answered with a JSON-RPC result and HTTP "
            f"{response.status}; the client has no id to correlate it with",
            evidence=f"HTTP {response.status}",
        )
    return RuleResult.failed(
        f"a notification was answered with HTTP {response.status}; expected 202 or an "
        "error status",
    )
```

The remaining four follow the same shape and are mechanical:

| Rule | Provocation | PASS | FAIL |
|---|---|---|---|
| `unknown-method-http-404` | `probe.call("sentinel/definitely-not-a-real-method")` | `status == 404` and `error_code() == -32601` | served, or `-32601` without 404, or 404 without `-32601` |
| `protocol-version-header-required` | `probe.tools_list(omit_protocol_version_header=True)` | `status == 400` and `error_code() == -32020` | served; or rejected without 400/-32020 |
| `protocol-version-header-body-mismatch-rejected` | `probe.tools_list(protocol_version_header="2025-11-25")` — header says one version, body's `_meta` says `2026-07-28` | `status == 400` and `error_code() == -32020` | served (a gateway routing on the header would have authorized a different version than the one that ran) |
| `response-content-type-valid` | `probe.tools_list()` | `headers["content-type"]` starts with `application/json` or `text/event-stream` | anything else |

And one SHOULD, in `should/http.py` (create it, add to `should/__init__.py`): `get-delete-405` — issue a bare `GET` and `DELETE` to the endpoint via `probe._transport._client` and expect `405`; `NOT_APPLICABLE` if the endpoint is unreachable.

Tighten in `headers.py`, keeping both ids: `mcp_method_required` and `header_mismatch_rejected` must now require **both** `-32020` and HTTP 400, per *"servers **MUST** return HTTP status `400 Bad Request` and **MUST** include a JSON-RPC error response"*. Today `mcp_method_required` accepts `status >= 400` **or** any error code, and `header_mismatch_rejected` does not look at status at all. This narrows what passes without changing what the rule means, so the ids stay; say so in the commit.

- [ ] **Step 4: Seed the fixtures and run**

`nonconformant.py`: serve unknown methods with HTTP 200, ignore `Origin`, accept a mismatched protocol-version header, answer notifications with a result, and return `text/plain`. Tag each and extend `SEEDED_VIOLATIONS`.
`conformant.py`: implement all six correctly.

Run: `uv run pytest tests/harness -m unit -q && uv run sentinel catalog validate`

- [ ] **Step 5: Verify the broker still passes, then commit and PR**

```bash
export PATH="/opt/homebrew/bin:$PATH"
make up && make scan-broker
```

The broker will likely FAIL `protocol-version-header-required` and `invalid-origin-rejected` — it validates `Mcp-Method`/`Mcp-Name` but nothing in `headers.go` mentions `MCP-Protocol-Version` or `Origin`. **That is the harness working.** Fix the broker in the same PR: extend `broker/internal/transport/headers.go` to require and cross-check `MCP-Protocol-Version`, and add an `Origin` allowlist to `transport.Server` (config key `BROKER_ALLOWED_ORIGINS`, default empty = reject any request that carries an `Origin` at all, since a server with no browser clients should have none).

```bash
make check && make scan-broker
git add -A
git commit -m "feat: the HTTP layer -- status codes, Origin, Content-Type, notifications

And the broker fixes the harness found: it validated Mcp-Method and Mcp-Name
and never looked at MCP-Protocol-Version or Origin."
git push -u origin feat/wp-16-http-layer && gh pr create --fill
```

---

# WP-17 — MRTR and the primitives with no coverage

**Branch:** `feat/wp-17-mrtr-primitives`

Implements spec §6.3 and §6.4.

---

### Task 14: `must/mrtr.py`

**Files:**
- Create: `harness/src/sentinel/catalog/must/mrtr.py`
- Modify: `harness/src/sentinel/catalog/must/__init__.py`
- Test: `tests/harness/test_catalog.py`

**Interfaces:**
- Consumes: `Probe.prompts_get`, `Probe.tools_call`, `client_capabilities` override
- Produces: `input-required-carries-requests-or-state`, `input-requests-shape-valid`, `input-required-only-on-supported-requests`, `input-requests-respect-declared-capabilities`, `tampered-requeststate-rejected`

**Quotes, verified from `basic/patterns/mrtr` §Server Requirements:**
- *"Servers **MUST** include at least one of `inputRequests` or `requestState` in every `InputRequiredResult` response."*
- *"`inputRequests` values are request objects that **MUST** be one of `ElicitRequest`, `CreateMessageRequest`, or `ListRootsRequest`"*
- *"Servers **MUST NOT** send `InputRequiredResult` responses on any other client requests."* (supported: `prompts/get`, `resources/read`, `tools/call`)
- *"Servers **MUST NOT** send an `inputRequests` that the client has not declared support for in its capabilities."*
- *"servers **MUST** treat `requestState` as an attacker-controlled input… **MUST** protect its integrity… and **MUST** reject state that fails verification. Integrity protection **MAY** be omitted only when tampering can cause nothing worse than request failure."*

> **Note on a rule NOT to write.** *"The JSON-RPC `id` **MUST** be different between the initial request and the retry"* is under **Client** Requirements. It is not a server obligation and there is no server-side rule to write for it.

- [ ] **Step 1: Write the failing test**

Add to `tests/harness/test_catalog.py` the parametrised conformant-passes / nonconformant-fails pair over:

```python
MRTR_RULES = [
    "MCP/2026-07-28/MUST/input-required-carries-requests-or-state",
    "MCP/2026-07-28/MUST/input-requests-shape-valid",
    "MCP/2026-07-28/MUST/input-required-only-on-supported-requests",
    "MCP/2026-07-28/MUST/input-requests-respect-declared-capabilities",
    "MCP/2026-07-28/MUST/tampered-requeststate-rejected",
]
```

For the conformant fixture, `NOT_APPLICABLE` is an acceptable outcome for rules that need the server to actually return `input_required` — assert `outcome in (PASS, NOT_APPLICABLE)`. For the non-conformant fixture assert `FAIL`, which means that fixture must return a *badly shaped* `input_required` (Step 4).

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/harness/test_catalog.py -q -k mrtr_rules` → FAIL, `KeyError`.

- [ ] **Step 3: Implement**

Create `harness/src/sentinel/catalog/must/mrtr.py`:

```python
"""MUST rules for Multi Round-Trip Requests.

MRTR is what replaced server-initiated requests wholesale. Correlation happens
through the sealed `requestState`, never the JSON-RPC id, and the state travels
through the client -- which is why the specification calls it attacker-controlled
input and requires that tampering be caught.
"""

from __future__ import annotations

from typing import Any

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe
from sentinel.probe.transport import RawResponse

MRTR = f"{SPEC_BASE}/basic/patterns/mrtr"

#: The only methods that may answer with an InputRequiredResult.
SUPPORTED = ("prompts/get", "resources/read", "tools/call")

#: The only request objects an inputRequests map may contain.
ALLOWED_INPUT_METHODS = {"elicitation/create", "sampling/createMessage", "roots/list"}


def _input_required(response: RawResponse) -> dict[str, Any] | None:
    """The result, if the server asked for input; None otherwise."""
    result = response.result()
    if result is None or result.get("resultType") != "input_required":
        return None
    return result


def _provoke(probe: Probe) -> list[tuple[str, dict[str, Any]]]:
    """Every input_required the probe can elicit from a supported method."""
    found: list[tuple[str, dict[str, Any]]] = []
    name = probe.first_tool_name()
    if name is not None:
        result = _input_required(probe.tools_call(name, {}))
        if result is not None:
            found.append(("tools/call", result))
    for method, send in (
        ("resources/read", lambda: probe.resources_read("sentinel://probe")),
        ("prompts/get", lambda: probe.prompts_get("sentinel-probe")),
    ):
        result = _input_required(send())
        if result is not None:
            found.append((method, result))
    return found


@rule(
    id="MCP/2026-07-28/MUST/input-required-carries-requests-or-state",
    title="Every input_required result carries inputRequests or requestState",
    severity=Severity.MUST,
    citation=f"{MRTR}#server-requirements-basic-workflow",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Include at least one of inputRequests or requestState in every "
        "InputRequiredResult. With neither, the client learns that the call is "
        "incomplete and nothing about what to supply or how to resume, so the only "
        "move left is to retry the identical request and get the identical answer."
    ),
    introduced_in="0.2.0",
)
def input_required_carries_requests_or_state(probe: Probe) -> RuleResult:
    found = _provoke(probe)
    if not found:
        return RuleResult.not_applicable("this server never returned an input_required result")
    bad = [
        method
        for method, result in found
        if "inputRequests" not in result and "requestState" not in result
    ]
    if bad:
        return RuleResult.failed(
            f"input_required from {bad} carried neither inputRequests nor requestState"
        )
    return RuleResult.passed(f"{len(found)} input_required result(s) carry one or both")


@rule(
    id="MCP/2026-07-28/MUST/input-requests-shape-valid",
    title="inputRequests contains only elicitation, sampling or roots requests",
    severity=Severity.MUST,
    citation=f"{MRTR}#server-requirements-basic-workflow",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Restrict inputRequests values to ElicitRequest, CreateMessageRequest or "
        "ListRootsRequest. A client implements handlers for exactly those three; "
        "anything else is a request it has no way to fulfil, so the flow cannot "
        "complete."
    ),
    introduced_in="0.2.0",
)
def input_requests_shape_valid(probe: Probe) -> RuleResult:
    found = _provoke(probe)
    if not found:
        return RuleResult.not_applicable("this server never returned an input_required result")
    offenders: list[str] = []
    checked = 0
    for method, result in found:
        requests = result.get("inputRequests")
        if not isinstance(requests, dict):
            continue
        for key, request in requests.items():
            checked += 1
            asked = request.get("method") if isinstance(request, dict) else None
            if asked not in ALLOWED_INPUT_METHODS:
                offenders.append(f"{method} asked for {asked!r} under key {key!r}")
    if offenders:
        return RuleResult.failed(
            f"{len(offenders)} inputRequests entries are not one of the three allowed "
            f"request types: {offenders}",
            evidence="; ".join(offenders),
        )
    if checked == 0:
        return RuleResult.not_applicable("no input_required result carried inputRequests")
    return RuleResult.passed(f"all {checked} inputRequests entries are a permitted type")


@rule(
    id="MCP/2026-07-28/MUST/input-required-only-on-supported-requests",
    title="input_required is never returned on a method that does not support it",
    severity=Severity.MUST,
    citation=f"{MRTR}#supported-requests",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Return InputRequiredResult only from prompts/get, resources/read and "
        "tools/call. A client retries the request it sent; for a list method there is "
        "no per-call input to gather, so the retry is identical and the flow cannot "
        "terminate."
    ),
    introduced_in="0.2.0",
)
def input_required_only_on_supported_requests(probe: Probe) -> RuleResult:
    unsupported = [
        ("server/discover", probe.discover),
        ("tools/list", probe.tools_list),
        ("resources/list", probe.resources_list),
        ("resources/templates/list", probe.resource_templates_list),
        ("prompts/list", probe.prompts_list),
    ]
    offenders = [name for name, send in unsupported if _input_required(send()) is not None]
    if offenders:
        return RuleResult.failed(
            f"{offenders} answered with resultType input_required; only "
            f"{list(SUPPORTED)} may",
            evidence=f"input_required from: {offenders}",
        )
    return RuleResult.passed(
        f"none of the {len(unsupported)} unsupported methods returned input_required"
    )


@rule(
    id="MCP/2026-07-28/MUST/input-requests-respect-declared-capabilities",
    title="No input is requested that the client did not declare it can provide",
    severity=Severity.MUST,
    citation=f"{MRTR}#server-requirements-basic-workflow",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Read io.modelcontextprotocol/clientCapabilities and ask only for what it "
        "declares. Asking a client that cannot elicit for an elicitation produces a "
        "flow it can never complete: it cannot supply the input and it cannot proceed "
        "without it."
    ),
    introduced_in="0.2.0",
)
def input_requests_respect_declared_capabilities(probe: Probe) -> RuleResult:
    # The probe declares {} -- it genuinely cannot sample, elicit or serve roots.
    # So ANY inputRequests coming back is a request for a capability that was not
    # declared, which makes this rule unusually crisp.
    found = _provoke(probe)
    if not found:
        return RuleResult.not_applicable("this server never returned an input_required result")
    offenders = [
        f"{method} asked for {sorted(result['inputRequests'])}"
        for method, result in found
        if isinstance(result.get("inputRequests"), dict) and result["inputRequests"]
    ]
    if offenders:
        return RuleResult.failed(
            "the probe declared clientCapabilities {} -- it can neither elicit, sample "
            f"nor serve roots -- and was asked anyway: {offenders}",
            evidence="; ".join(offenders),
        )
    return RuleResult.passed(
        "no inputRequests were sent to a client that declared no capabilities"
    )


@rule(
    id="MCP/2026-07-28/MUST/tampered-requeststate-rejected",
    title="A modified requestState never completes the request",
    severity=Severity.MUST,
    citation=f"{MRTR}#security-considerations",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Seal requestState with an AEAD or HMAC and reject anything that fails "
        "verification. The state travels through the client, so it is attacker-"
        "controlled by construction; if it carries a principal, a tenant or an "
        "approval, an unsealed blob lets the caller rewrite the decision the server "
        "already made."
    ),
    introduced_in="0.2.0",
)
def tampered_requeststate_rejected(probe: Probe) -> RuleResult:
    found = [(m, r) for m, r in _provoke(probe) if isinstance(r.get("requestState"), str)]
    if not found:
        return RuleResult.not_applicable(
            "this server never returned a requestState to tamper with"
        )

    method, result = found[0]
    original = result["requestState"]
    if not original:
        return RuleResult.not_applicable("requestState was empty")

    # Flip one character in the middle. A truncation or a garbage string might be
    # rejected by a length check that is not an integrity check; a single altered
    # byte in a well-formed blob is what an integrity check is for.
    middle = len(original) // 2
    swapped = "B" if original[middle] != "B" else "C"
    tampered = original[:middle] + swapped + original[middle + 1 :]

    params: dict[str, Any] = {"requestState": tampered, "inputResponses": {}}
    if method == "tools/call":
        params["name"] = probe.first_tool_name() or "sentinel-no-such-tool"
        params["arguments"] = {}
    elif method == "resources/read":
        params["uri"] = "sentinel://probe"
    else:
        params["name"] = "sentinel-probe"

    response = probe.call(method, params)
    if not response.reached_server:
        return RuleResult.indeterminate(f"unreachable: {response.transport_error}")

    if response.error() is not None:
        return RuleResult.passed(
            f"a requestState with one byte changed was rejected "
            f"(code {response.error_code()})"
        )
    completed = response.result()
    if completed is not None and completed.get("resultType") == "complete":
        return RuleResult.failed(
            f"a requestState with one byte changed was accepted and {method} ran to "
            "completion; the state is not integrity-protected, so a client can rewrite "
            "whatever the server sealed into it",
            evidence=f"tampered byte at index {middle}; resultType complete",
        )
    # A fresh input_required, or any other non-completing answer, means tampering
    # caused nothing worse than request failure -- which the spec permits.
    return RuleResult.passed(
        "a tampered requestState did not complete the request; tampering caused "
        "nothing worse than failure, which the specification permits"
    )
```

Add `mrtr` to `must/__init__.py`.

- [ ] **Step 4: Seed the fixtures**

`nonconformant.py` must now return an `input_required` result that is wrong in every way at once: on `tools/list` (unsupported method), with an `inputRequests` entry whose `method` is `"server/pleaseDoThis"` (invalid shape), asking despite `clientCapabilities: {}`, and with a `requestState` it never verifies. Tag each rule id and extend `SEEDED_VIOLATIONS`.

`conformant.py` gains a minimal correct MRTR flow: `tools/call` on a tool named `confirm` returns `input_required` with `requestState` only (no `inputRequests`, since the probe declares no capabilities — which is itself the correct behaviour under `input-requests-respect-declared-capabilities`), and a retry with a modified `requestState` returns an error. Sealing can be a plain HMAC with a process-local key; the fixture is not a security product, but it must actually verify.

- [ ] **Step 5: Run and commit**

```bash
uv run pytest tests/harness -m unit -q && uv run sentinel catalog validate
git checkout -b feat/wp-17-mrtr-primitives
git add -A && git commit -m "feat: MRTR rules, including the forged-requestState test the probe was built for

HANDOFF 9.4 designed the probe to send 'a forged requestState' and no rule ever
used it. It does now, and it flips one byte in the middle rather than sending
garbage: a length check will catch garbage, and a length check is not an
integrity check."
```

---

### Task 15: `must/primitives.py` — `resources/read`, `prompts/get`, capability truthfulness

**Files:**
- Create: `harness/src/sentinel/catalog/must/primitives.py`
- Modify: `harness/src/sentinel/catalog/must/__init__.py`
- Modify: `harness/src/sentinel/catalog/must/envelope.py` (`LIST_ENDPOINTS` comment only)
- Test: `tests/harness/test_catalog.py`

**Interfaces:**
- Consumes: `Probe.prompts_get` from WP-16 Task 11
- Produces: `tool-call-result-type-present`, `resources-read-result-type-present`, `prompts-get-result-type-present`, `resources-read-carries-ttl`, `resources-read-carries-scope`, `resource-read-no-empty-contents-for-missing`, `tools-capability-matches-tools-list`, `resources-capability-matches-resources-list`, `prompts-capability-matches-prompts-list`, `resource-subscribe-advertised-truthfully`

**Why:** `LIST_ENDPOINTS` in `must/envelope.py` covers `server/discover`, `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list` — and excludes `tools/call`, `resources/read` and `prompts/get`, three of the most-invoked methods in the protocol. The changelog names `resources/read` explicitly among the endpoints requiring `CacheableResult`; it is not in the set. And *"The `result` **MUST** include a `resultType` field"* is universal, not list-specific.

**Quotes:** *"Servers that support tools **MUST** declare the `tools` capability"* / *"Servers that declare the `tools` capability **MUST** respond to `tools/list` requests"* (and the identical pair on the resources and prompts pages).

- [ ] **Step 1: Write the failing test**

Same parametrised pair, over the ten ids above. For a target with no resources or prompts, `NOT_APPLICABLE` is correct and the conformant assertion must accept it.

- [ ] **Step 2: Run to verify it fails** — `KeyError`.

- [ ] **Step 3: Implement**

The envelope rules follow the shape already in `must/envelope.py`, applied to a different set of senders. The capability-truthfulness rules are the interesting ones — both directions, from one `server/discover`:

```python
def _capability_matches(
    probe: Probe, capability: str, method: str, payload_key: str
) -> RuleResult:
    discovered = probe.discover().result()
    if discovered is None:
        return RuleResult.indeterminate("server/discover returned no result")
    capabilities = discovered.get("capabilities")
    if not isinstance(capabilities, dict):
        return RuleResult.indeterminate("capabilities is not an object")

    declared = capability in capabilities
    response = probe.call(method)
    result = response.result()
    answers = isinstance(result, dict) and isinstance(result.get(payload_key), list)

    if declared and not answers:
        return RuleResult.failed(
            f"capabilities declares {capability!r} but {method} did not return a "
            f"{payload_key} array (code {response.error_code()}); a client that trusts "
            "discovery will call a method that does not work",
            evidence=f"declared={declared}, {method} answered {response.status}",
        )
    if answers and not declared:
        return RuleResult.failed(
            f"{method} works but capabilities does not declare {capability!r}; a client "
            "reading discovery will never call it, so the feature is invisible",
            evidence=f"declared={declared}, {payload_key} present",
        )
    return RuleResult.passed(
        f"{capability!r} declared={declared} and {method} "
        f"{'answers' if answers else 'does not answer'} -- they agree"
    )
```

with three thin rules over it: `("tools", "tools/list", "tools")`, `("resources", "resources/list", "resources")`, `("prompts", "prompts/list", "prompts")`.

`resource-subscribe-advertised-truthfully` mirrors the existing `list-changed-advertised-truthfully` in `must/discovery.py` — read that rule and follow it exactly, substituting `capabilities.resources.subscribe` for the `listChanged` flags and `subscriptions/listen` for the same control probe. The existing rule only inspects `listChanged`, so a server claiming `subscribe: true` slides past it entirely.

`resource-read-no-empty-contents-for-missing`: `probe.resources_read("sentinel://no/such/resource")`; FAIL if the result is `{"contents": []}` with no error — an empty array is indistinguishable from a resource that exists and is empty, so the client cannot tell "not found" from "found, nothing in it".

- [ ] **Step 4: Fixtures, run, commit**

Seed each in `nonconformant.py` with tags and `SEEDED_VIOLATIONS` entries; implement each correctly in `conformant.py`.

```bash
uv run pytest tests/harness -m unit -q && uv run sentinel catalog validate
make up && make scan-broker    # the broker may fail the resources/prompts capability rules
git add -A && git commit -m "feat: cover tools/call, resources/read and prompts/get, and capability truthfulness both ways"
git push -u origin feat/wp-17-mrtr-primitives && gh pr create --fill
```

---

# WP-18 — Tool schemas, `x-mcp-header`, and the NOT_APPLICABLE fixture

**Branch:** `feat/wp-18-schemas`

Implements spec §6.5, §6.6 and §6.7.

---

### Task 16: `must/schemas.py` — the `x-mcp-header` constraint set

**Files:**
- Create: `harness/src/sentinel/catalog/must/schemas.py`
- Modify: `harness/src/sentinel/catalog/must/__init__.py`
- Test: `tests/harness/test_schemas.py` (create — these are pure functions over a manifest, so they get direct unit tests as well as fixture tests)

**Interfaces:**
- Produces: `x-mcp-header-not-empty`, `x-mcp-header-token-syntax`, `x-mcp-header-no-control-characters`, `x-mcp-header-case-insensitively-unique`, `x-mcp-header-primitive-types-only`, `x-mcp-header-statically-reachable`, `tools-declare-valid-input-schema`, `no-retired-error-codes-emitted`

**Quotes, verbatim from `basic/transports/streamable-http` §Schema Extension.** Constraints on `x-mcp-header` values:
- *"**MUST NOT** be empty"*
- *"**MUST** match HTTP field-name token syntax (`1*tchar`, RFC 9110 Section 5.1)"*
- *"**MUST NOT** contain control characters, including carriage return (CR, `\r`) or line feed (LF, `\n`)"*
- *"**MUST** be case-insensitively unique among all `x-mcp-header` values in the `inputSchema`"*
- *"**MUST** only be applied to parameters with primitive types (integer, string, boolean). Parameters with type `number` are not permitted."*
- *"**MUST** only be applied to properties that are *statically reachable* from the schema root: reachable via a chain consisting solely of `properties` keys. The chain **MUST NOT** pass through `items` (or any other array keyword), composition keywords (`oneOf`, `anyOf`, `allOf`, `not`), conditional keywords (`if`/`then`/`else`), or `$ref`."*

And the consequence that makes these worth a MUST: *"Clients using the Streamable HTTP transport **MUST** reject tool definitions where any `x-mcp-header` value violates these constraints. Rejection means the client **MUST** exclude the invalid tool from the result of `tools/list`."* A server that ships one of these ships a tool that conforming clients silently drop.

- [ ] **Step 1: Write the failing test**

Create `tests/harness/test_schemas.py` with direct unit tests over the walker, no server needed:

```python
"""x-mcp-header constraints, checked against a manifest rather than a server.

These are the only rules in the catalog that need one tools/list response and
nothing else, so they get unit tests over literal schemas -- which is also the
only practical way to cover the statically-reachable rules, since a fixture
would need one tool per violation.
"""

from __future__ import annotations

import pytest

from sentinel.catalog.schemas import HeaderAnnotation, walk_header_annotations

pytestmark = pytest.mark.unit


def test_finds_a_top_level_annotation() -> None:
    schema = {"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}}
    found = walk_header_annotations(schema)
    assert found == [HeaderAnnotation(name="Region", path=("region",), reachable=True, type_="string")]


def test_finds_a_nested_object_annotation_and_calls_it_reachable() -> None:
    schema = {
        "type": "object",
        "properties": {
            "target": {
                "type": "object",
                "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
            }
        },
    }
    found = walk_header_annotations(schema)
    assert found[0].path == ("target", "region")
    assert found[0].reachable is True


@pytest.mark.parametrize(
    "wrapper",
    [
        {"items": {"type": "object", "properties": {"r": {"type": "string", "x-mcp-header": "R"}}}},
        {"oneOf": [{"properties": {"r": {"type": "string", "x-mcp-header": "R"}}}]},
        {"anyOf": [{"properties": {"r": {"type": "string", "x-mcp-header": "R"}}}]},
        {"allOf": [{"properties": {"r": {"type": "string", "x-mcp-header": "R"}}}]},
        {"not": {"properties": {"r": {"type": "string", "x-mcp-header": "R"}}}},
        {"if": {"properties": {"r": {"type": "string", "x-mcp-header": "R"}}}},
        {"then": {"properties": {"r": {"type": "string", "x-mcp-header": "R"}}}},
        {"else": {"properties": {"r": {"type": "string", "x-mcp-header": "R"}}}},
        {"$defs": {"d": {"properties": {"r": {"type": "string", "x-mcp-header": "R"}}}}},
    ],
)
def test_annotations_behind_a_forbidden_keyword_are_not_reachable(wrapper: dict) -> None:
    """"The chain MUST NOT pass through items, composition keywords, conditional
    keywords, or $ref.\""""
    found = walk_header_annotations({"type": "object", **wrapper})
    assert found, "the annotation should still be FOUND, so it can be reported"
    assert all(not a.reachable for a in found)


def test_control_characters_are_detected() -> None:
    schema = {"type": "object", "properties": {"a": {"type": "string", "x-mcp-header": "X\r\nInjected: 1"}}}
    assert walk_header_annotations(schema)[0].name == "X\r\nInjected: 1"
```

Then add the fixture-oracle pair in `tests/harness/test_catalog.py` over the eight rule ids.

- [ ] **Step 2: Run to verify it fails** — `ModuleNotFoundError: sentinel.catalog.schemas`.

- [ ] **Step 3: Implement the walker**

Create `harness/src/sentinel/catalog/schemas.py` (the pure logic, importable and testable without a server):

```python
"""Walking a tool inputSchema for x-mcp-header annotations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

#: RFC 9110 §5.1 tchar.
TCHAR = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

#: Types that may carry an annotation. `number` is excluded by name in the spec.
PRIMITIVE_TYPES = {"integer", "string", "boolean"}

#: Keywords a statically-reachable chain MUST NOT pass through.
FORBIDDEN_KEYWORDS = (
    "items", "prefixItems", "additionalItems", "contains",
    "oneOf", "anyOf", "allOf", "not",
    "if", "then", "else",
    "$ref", "$defs", "definitions",
    "additionalProperties", "patternProperties", "propertyNames",
)


@dataclass(frozen=True, slots=True)
class HeaderAnnotation:
    name: str
    path: tuple[str, ...]
    #: True when every step from the root was a `properties` key.
    reachable: bool
    type_: str | None


def walk_header_annotations(schema: object) -> list[HeaderAnnotation]:
    """Every x-mcp-header in `schema`, reachable or not.

    Unreachable annotations are RETURNED rather than skipped: an annotation the
    client will reject the whole tool over is exactly what a scan must report,
    and skipping it would make the tool look clean.
    """
    found: list[HeaderAnnotation] = []

    def visit(node: object, path: tuple[str, ...], reachable: bool) -> None:
        if not isinstance(node, dict):
            return
        raw = node.get("x-mcp-header")
        if isinstance(raw, str) or raw is not None:
            declared = node.get("type")
            found.append(
                HeaderAnnotation(
                    name=raw if isinstance(raw, str) else str(raw),
                    path=path,
                    reachable=reachable,
                    type_=declared if isinstance(declared, str) else None,
                )
            )
        properties = node.get("properties")
        if isinstance(properties, dict):
            for key, child in properties.items():
                visit(child, (*path, str(key)), reachable)
        for keyword in FORBIDDEN_KEYWORDS:
            branch = node.get(keyword)
            if isinstance(branch, dict):
                # Same path, but the chain is broken from here down.
                visit(branch, path, False)
            elif isinstance(branch, list):
                for child in branch:
                    visit(child, path, False)

    visit(schema, (), True)
    return found
```

Create `harness/src/sentinel/catalog/must/schemas.py` with a shared helper that collects every tool's annotations once and eight rules over it. Each rule reports the tool name and the property path, because *"Rejection means the client MUST exclude the invalid tool"* — the reader needs to know which tool disappears. Remediation for `x-mcp-header-no-control-characters` must say what it actually is:

```python
    remediation=(
        "Remove control characters from every x-mcp-header value. A CR or LF in a "
        "header name is header injection: a client that mirrors it produces a request "
        "with a header boundary the server never intended. Conforming clients drop the "
        "whole tool rather than send it, so the tool is unusable either way."
    ),
```

`no-retired-error-codes-emitted` is separate and simple: provoke the same five errors `should/errors.py` uses and FAIL on `-32002` or `-32042` — *"Implementations of this protocol version **MUST NOT** emit these codes."*

`tools-declare-valid-input-schema` strengthens the existing presence check: *"**MUST** be a valid JSON Schema object (not `null`)"* — the value must be a dict, must not be `None`, and if it declares `type` it must be `"object"`.

- [ ] **Step 4: Fixtures, run, commit**

`nonconformant.py` grows one tool per constraint (`x-mcp-header: ""`, `"Bad Header"`, `"X\r\nInjected: 1"`, a case-insensitive duplicate pair, one on a `number`, one behind `items`), each tagged; extend `SEEDED_VIOLATIONS`. `conformant.py` gets one tool with a correct annotation, so the PASS path is exercised rather than only the `NOT_APPLICABLE` one.

```bash
uv run pytest tests/harness -m unit -q && uv run sentinel catalog validate
git checkout -b feat/wp-18-schemas
git add -A && git commit -m "feat: the x-mcp-header constraint set, including CRLF injection in a header name"
```

---

### Task 17: `should/naming.py`, the `partial` fixture, and the measurements

**Files:**
- Create: `harness/src/sentinel/catalog/should/naming.py`
- Create: `fixtures/server/partial.py`
- Modify: `tests/harness/conftest.py`
- Modify: `scripts/measure.py`, `MEASUREMENTS.md`
- Modify: `harness/src/sentinel/cli.py` (`fixture serve --profile partial`)

**Interfaces:**
- Produces: `SHOULD/tool-names-well-formed`, `SHOULD/tool-names-unique-within-server`; pytest fixture `partial_endpoint`

**Quotes:** all SHOULD, so all SHOULD rules — *"Tool names **SHOULD** be between 1 and 128 characters in length"*, *"The following **SHOULD** be the only allowed characters: uppercase and lowercase ASCII letters (A-Z, a-z), digits (0-9), underscore (`_`), hyphen (`-`), and dot (`.`)"*, *"Tool names **SHOULD** be unique within a server."*

- [ ] **Step 1: Write the failing test**

```python
def test_every_rule_that_can_be_not_applicable_has_been(partial_endpoint: str) -> None:
    """A NOT_APPLICABLE branch no test has taken has never been checked.

    `partial` serves tools and nothing else: no resources, no prompts, no MRTR.
    Every rule must return a verdict rather than raising, and the rules that
    constrain a feature this server does not have must say NOT_APPLICABLE rather
    than FAIL -- failing a server for not implementing an optional feature is the
    other way a scanner loses trust.
    """
    from sentinel.grade import run_scan
    from sentinel.catalog.base import Outcome, Severity

    report = run_scan(partial_endpoint)
    assert report.findings, "the scan produced no findings at all"

    unexpected = [
        f.rule.id
        for f in report.findings
        if f.result.outcome is Outcome.FAIL
        and f.rule.severity is Severity.MUST
        and ("resources" in f.rule.id or "prompts" in f.rule.id or "input-" in f.rule.id)
    ]
    assert not unexpected, f"rules failed a server that simply lacks the feature: {unexpected}"

    assert any(f.result.outcome is Outcome.NOT_APPLICABLE for f in report.findings)
```

- [ ] **Step 2: Run to verify it fails** — `fixture 'partial_endpoint' not found`.

- [ ] **Step 3: Implement**

Create `fixtures/server/partial.py` modelled directly on `conformant.py` — same envelope, cache and header logic, correct in every respect — but advertising only `capabilities: {"tools": {"listChanged": False}}`, serving `tools/list` and `tools/call`, and answering `resources/list`, `resources/templates/list`, `prompts/list`, `resources/read` and `prompts/get` with `-32601`. It never returns `input_required`. Import nothing from `sentinel`, exactly as the other two fixtures do.

Add a session-scoped `partial_endpoint` fixture to `tests/harness/conftest.py` following the two already there, and `partial` to the `--profile` choices in `cli.py`'s `fixture serve`.

Create `should/naming.py` with the two rules. `tool-names-well-formed` checks length 1–128 and the character allowlist `^[A-Za-z0-9._-]+$`, reporting each offending name and which constraint it broke.

- [ ] **Step 4: Regenerate the measurements**

```bash
export PATH="/opt/homebrew/bin:$PATH"
make up
make measure
```

`MEASUREMENTS.md` is generated — **do not edit it by hand.** If `scripts/measure.py` computes recall over MUST rules only, extend it to report recall per severity, since `SEEDED_VIOLATIONS` now contains SHOULD entries too. Add a row for the catalog size so the growth from 35 to ~74 is a published number rather than a claim.

- [ ] **Step 5: Full verification and PR**

```bash
make check
make up && make scan-broker && make scan-fixture ; echo "fixture exit $? (1 expected)"
make demo
uv run sentinel scan --endpoint http://localhost:8080/mcp --gate must --include-deprecated-rules
git add -A
git commit -m "feat: tool-name SHOULDs, a fixture with nothing optional, and measurements for the bigger catalog

partial.py serves tools and nothing else. Every NOT_APPLICABLE branch in the
catalog now has a test that takes it -- a branch no test has entered has never
been checked, and failing a server for not implementing an optional feature is
the other way a scanner loses trust."
git push -u origin feat/wp-18-schemas && gh pr create --fill
```

---

## Self-review

Checked against `docs/superpowers/specs/2026-08-23-sentinel-v1-design.md`:

**Spec coverage.** §3.1 → WP-15 Tasks 8–10. §3.2 → WP-14 Tasks 1, 4, 5. §3.3 → WP-14 Task 3 (widened to three probe defects after verifying the transport page). §3.4 → WP-14 Task 6. §4.1 → WP-14 Tasks 1–2. §4.2 → WP-16 Task 11. §6.1 → Task 12. §6.2 → Task 13. §6.3 → Task 14. §6.4 → Task 15. §6.5 → Task 16. §6.6, §6.7 → Task 17.

**Deferred, deliberately, with the work package that picks each up:**
- §4.3 concurrency → WP-22
- §4.4 report schema v2 → WP-24
- §5 gray-box evidence → WP-21
- §7 config, waivers, baselines, and the per-rule `evidence_key` → WP-19/WP-20. `evidence_key` is *not* added in WP-14: it would mean editing all 35 existing rules for a field nothing reads until fingerprints exist.
- §8 the rest of the beyond-spec namespace and `--gate security` → WP-23. WP-14 ships the namespace and one rule because `tools-sorted-by-name` needs a successor to point at, and `validate_registry` requires a successor that exists.
- §9–§12 → WP-22 onward.

**Corrections made while writing, against verified spec text:**
- `mrtr-retry-requires-new-id` was **dropped**. The new-id requirement is under *Client* Requirements; there is no server obligation to test.
- `notification-returns-202` was **reframed** as `notification-not-answered-with-a-result`. The 202 is conditional — *"If the server cannot accept it, it MUST return an HTTP error status"* — and this revision defines no client-to-server notifications over Streamable HTTP, so demanding 202 outright would be a false positive.
- `get-delete-405` is **SHOULD**, not MUST — it appears under Backward Compatibility as *"SHOULD respond as follows"*.
- `invalid-origin-rejected` uses a `.invalid` origin (RFC 2606) so that a served request is evidence of no validation rather than of a permissive allowlist, and returns `INDETERMINATE` on any non-403 refusal.
- WP-16 Task 11 adds an audit of `mcp-name-header-required`: `Mcp-Name` is required for three methods, not *"All requests"*.

**Type consistency.** `walk_header_annotations` / `HeaderAnnotation` are named identically in Task 16's tests and implementation. `Registry.all(include_deprecated=)` has the same keyword everywhere. `checks.server_info_echoed` / `checks.tools_list_deterministic` / `checks.tools_sorted_by_name` match between `checks.py`, `must/envelope.py`, `should/envelope.py` and `beyond/style.py`. `Probe.build_notification` returns `Request` and `Probe.notify` returns `RawResponse` — the test in Task 11 uses `build_notification` for the id assertion and `notify` nowhere, which is correct since no server is running in a unit test.

**Known risk.** Tasks 13 and 15 will likely fail the broker (`MCP-Protocol-Version` validation, `Origin` validation, resources/prompts capability agreement). That is the harness doing its job, and each task fixes the broker in the same PR rather than weakening the rule.
