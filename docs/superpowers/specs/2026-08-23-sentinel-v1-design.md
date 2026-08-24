# Sentinel v1 — Design

**Document ID:** SN-DSN-002 · **Version:** 1.0 · **Date:** August 23, 2026
**Supersedes nothing.** Extends `SN-HND-001` (`docs/HANDOFF.md`) from the MVP tier to v1.
**Spec baseline:** [MCP `2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28/)

> Where this document and the MCP specification disagree, **the specification wins and this
> document is wrong.** That rule is not decorative: §3 below exists entirely because applying it
> found four places where the repository is currently wrong.

---

## 1. What v1 is

The MVP proved two things: a Go MCP server built natively on the stateless revision, and a harness
that grades any server against it. Neither is yet something a company adopts.

v1 turns the pair into three artifacts a company can actually take:

| Artifact | Language | What it is | Who runs it |
|---|---|---|---|
| **`sentinel`** | Python | The conformance and drift scanner. CLI, CI gate, fleet sweep. | Every team that operates or consumes an MCP server |
| **`mcp/`** | Go | The server kit extracted from `broker/internal/` — envelope, registry, transport, handles, MRTR, audit, authz. | Every team that *builds* an MCP server on `2026-07-28` |
| **`sentinel-server`** | Go | Fleet service: ingests scan reports, keeps history, computes drift and posture, serves an API and dashboard. | Platform / security teams with more than one MCP server |

`broker/` stops being the product and becomes the **reference application** built on `mcp/` — which
is a stronger claim than it was before. Today `broker` proves the spec can be implemented; after
v1 it proves the *kit* implements the spec, and the kit is the thing a stranger can use.

### 1.1 What does not change

The four rules in `CLAUDE.md` are unchanged. The harness still never imports server internals and
still runs against any endpoint URL. The probe is still deliberately literal with no MCP SDK. An
unverifiable MUST still returns `INDETERMINATE` and never a false pass. No model API key is
required anywhere, and `sentinel` still makes no network call except to the endpoint it is given.

---

## 2. Sources

Every normative claim in this document was fetched from the live specification on 2026-08-23 and is
quoted rather than paraphrased where it decides a design question. The pages used:

- `/specification/2026-07-28/basic` — envelope, `resultType`, error codes, `_meta`, statelessness
- `/specification/2026-07-28/server/tools` — capability, ordering, tool names, `x-mcp-header`
- `/specification/2026-07-28/deprecated` — the deprecation registry
- `/specification/2026-07-28/basic/transports/streamable-http` — header contract, HTTP statuses
- `/specification/2026-07-28/basic/patterns/mrtr` — MRTR server requirements
- `/specification/2026-07-28/basic/authorization` — 401 challenge shape

Where a rule cites the spec, the citation must resolve to a real page **and** a real anchor. The
existing catalog has anchors that do not obviously match live headings (`basic/lifecycle#server-identity`,
`#capabilities`); WP-14 verifies every citation in the catalog against a live fetch and fixes drift.

---

## 3. Verified spec debts — fixed first, because they are the credibility floor

A scanner is sold on rigor. Four things in the repository are currently wrong against the live
specification. All four are verified by direct quotation, not inference.

### 3.1 Broker's error codes occupy a range the specification retired

> **`-32000` to `-32019` — legacy.** Codes in this sub-range were allocated by implementations
> before this policy was introduced. New codes **MUST NOT** be allocated in this sub-range, and new
> implementations **SHOULD NOT** use codes from this sub-range at all.
>
> New error codes for purposes not defined by this specification **SHOULD** be allocated outside
> the JSON-RPC reserved range (`-32768` to `-32000`); the remainder of the integer space is
> available for application-defined errors.
>
> — MCP 2026-07-28, `basic` §Error Codes

`CLAUDE.md` and `HANDOFF.md` §7.2 both instruct that Sentinel's codes live in `-32000…-32019`.
`broker/internal/envelope/errors.go` implements that. Broker is a *new* implementation written in
2026; the sub-range is exactly what it should not use.

**Decision.** Sentinel's eight implementation-defined codes move to **`1000`–`1019`**, preserving
the low ordinal so triage knowledge transfers:

| Name | Was | Becomes |
|---|---|---|
| `HandleNotResolvable` | `-32000` | `1000` |
| `MRTRFlowExpired` | `-32001` | `1001` |
| `MRTRArgumentsMutated` | `-32003` | `1003` |
| `MRTRStateInvalid` | `-32004` | `1004` |
| `MRTRResultNoLongerAvailable` | `-32005` | `1005` |
| `TokenBudgetExceeded` | `-32006` | `1006` |
| `ScopeDenied` | `-32007` | `1007` |
| `AuditWriteFailed` | `-32008` | `1008` |

`1002` stays skipped for the same reason `-32002` was: it was resource-not-found before this
revision and reusing the ordinal makes triage ambiguous for clients mid-migration.

For one minor release the broker also emits `data.legacyCode` carrying the old value, so a client
mid-migration can triage on either. Controlled by `BROKER_EMIT_LEGACY_ERROR_CODE` (default `true`),
documented as scheduled for removal.

`envelope.IsSpecReserved` gains a sibling `IsLegacySubRange(code)`, and the existing
`TestNoErrorInReservedRange` gains `TestNoErrorInLegacySubRange` walking `AllCodes()`. A new harness
rule, `MCP/2026-07-28/SHOULD/no-errors-in-legacy-range`, checks the same property against any
server. It is a SHOULD because the spec grades it "SHOULD NOT use", not "MUST NOT emit".

`CLAUDE.md`, `HANDOFF.md` §7.2, `docs/MIGRATION.md` and the error-taxonomy comment block are all
updated. The recorded-divergence pattern in `docs/PRD.md` is the model: the change is written down
where a reader will find it, not silently applied.

### 3.2 Two rules grade SHOULDs as MUSTs, and one demands something the spec never asks for

`MEASUREMENTS.md` publishes "false positives against the conformant fixture: **0**", defined as "a
rule that fails here is demanding something the specification does not". The measurement is honest;
its fixture just happens not to exercise these three. Against a real server they would fire.

**`MUST/server-info-echoed`.** The spec's per-response table marks
`io.modelcontextprotocol/serverInfo` **Required: No**, under the sentence *"Servers **SHOULD**
include the following `io.modelcontextprotocol/*` field in every result's `_meta`."* This is a
SHOULD.

**`MUST/tools-list-is-deterministic`.** *"Servers **SHOULD** return tools in a deterministic order."*
This is a SHOULD. The MUST in the same paragraph is a different property — *"**MUST NOT** vary
per-connection or as a side effect of other requests on the connection"* — which the current rule
does not test, because all twenty of its calls share one `Probe`, and therefore one connection.

**`SHOULD/tools-sorted-by-name`.** The spec asks for *deterministic*, never for *sorted*. A server
returning a stable but unsorted list conforms fully and would fail this rule. It is not a spec rule
at any severity.

**Decision.** Rule IDs are permanent (§8.8: "deprecate and add rather than redefine, or every
historical report becomes uninterpretable"), so none of the three may be edited in place. §4.1
introduces the lifecycle mechanism this requires. Then:

| Rule | Action |
|---|---|
| `MUST/server-info-echoed` | deprecated, `superseded_by` → `SHOULD/server-info-echoed` (new) |
| `MUST/tools-list-is-deterministic` | deprecated, `superseded_by` → `SHOULD/tools-list-is-deterministic` (new) |
| — | **new** `MUST/tools-list-connection-independent`: two independent `Probe` instances, same credential, compared. The spec permits variance by authorization, so the credential must be held constant. |
| `SHOULD/tools-sorted-by-name` | deprecated, `superseded_by` → `SENTINEL/STYLE/tools-sorted-by-name` in the beyond-spec namespace (§8) |

### 3.3 The probe sends malformed requests

The spec's per-request table marks `io.modelcontextprotocol/clientCapabilities` **Required: Yes**,
and: *"A request missing any required field is malformed; the server **MUST** reject it with
JSON-RPC error code `-32602` (Invalid params). On HTTP, the response status **MUST** be `400 Bad
Request`."*

`probe/client.py` imports `KEY_CLIENT_CAPABILITIES` and never sets it. Every request the harness
sends is malformed. Against a server that enforces the rule, every rule in the catalog would fail
for the wrong reason — and the harness would report the server as broken.

(`clientInfo` is **Required: No**; the probe already sends it, which is correct and stays.)

**Decision.** `Probe.meta()` sends `clientCapabilities`, defaulting to `{}` — an honest declaration
that the probe supports no client capabilities, which is true: it cannot sample, elicit, or serve
roots. `Probe.build()` gains `omit_client_capabilities` and `client_capabilities=` overrides, since
the rules in §6.1 need to send a request deliberately missing the field.

This also unlocks a real rule: a server that *accepts* a request with no `clientCapabilities` is
violating a MUST, and until now the harness could not have noticed because it never sent one either
way.

### 3.4 The deprecation inventory reports wrong dates

`deprecations.py` gives all six features `DEPRECATED_ON = date(2026, 7, 28)` and computes removal as
`+12 months`. The registry disagrees on two, verbatim:

| Feature | Registry `Deprecated in` | Registry `Earliest removal` |
|---|---|---|
| Roots, Sampling, Logging, DCR | `2026-07-28` | First revision released on or after 2027-07-28 |
| `includeContext: "thisServer"` / `"allServers"` | **`2025-11-25`** | **Follows Sampling (SEP-2577)** |
| HTTP+SSE transport | **`2025-03-26`** | **Three months after SEP-2596 reaches Final** |

Two structural problems, not just two wrong constants. `includeContext`'s removal is *defined by
another feature's* removal, and HTTP+SSE's is *defined by an event that has not happened*. Neither
is expressible as `deprecated_on + 12 months`.

**Decision.** `DeprecatedFeature` gains a per-feature `deprecated_on` and a `removal: RemovalWindow`
that is one of three variants:

```python
@dataclass(frozen=True, slots=True)
class FixedRevision:      # "First revision released on or after <date>"
    on_or_after: datetime.date
@dataclass(frozen=True, slots=True)
class FollowsFeature:     # "Follows Sampling (SEP-2577)"
    feature_key: str
@dataclass(frozen=True, slots=True)
class AfterEvent:         # "Three months after SEP-2596 reaches Final"
    description: str
    sep: str
```

`FollowsFeature` resolves transitively to the followed feature's window. `AfterEvent` renders the
condition and **declines to invent a date** — the inventory prints "removable three months after
SEP-2596 reaches Final (not yet scheduled)" rather than a number it cannot know. Guessing a date
here is the same failure mode as scoring an unverifiable MUST as a pass.

A test asserts each feature's `deprecated_on` and removal condition against a checked-in transcript
of the registry table, so a future registry edit surfaces as a test failure rather than as silently
stale output.

---

## 4. Harness architecture changes

The current shape — `Registry` of `BaseRule`, a literal `Probe`, `run_scan` — is sound and stays.
What follows extends it; nothing here replaces it.

### 4.1 Rule lifecycle

`BaseRule` gains three fields:

```python
introduced_in: str            # sentinel version, e.g. "0.1.0"
deprecated_in: str | None     # sentinel version, None while live
superseded_by: str | None     # rule id, or None
```

`REGISTRY.all()` excludes deprecated rules by default. `--include-deprecated-rules` re-includes
them, reporting each with its successor named, so a team pinning an old report can still reproduce
it. `validate_registry()` enforces that a deprecated rule names a successor that exists, and that no
live rule shares a slug with a live rule of a different severity — which is what would otherwise let
`MUST/x` and `SHOULD/x` both fire and double-count.

This mechanism is what makes §3.2 executable without breaking §8.8's permanence guarantee. It is
also the thing that lets the catalog keep growing for years without accreting rules nobody dares
touch.

### 4.2 Probe: HTTP layer, more methods, connection control

`RawResponse` already carries `status`, lower-cased `headers`, and the raw body; no rule reads any
of them, and the spec mandates specific statuses in at least six places. So the work here is
consuming what exists and adding what does not.

- `Transport` gains `verify` (TLS: bool | CA bundle path), `proxy`, `client_cert`, and a bounded
  retry with backoff for *transport* failures only — never for a response the server actually sent,
  because retrying a served response would corrupt idempotency-sensitive rules.
- `Probe.new_connection()` returns a second `Probe` against the same endpoint with the same
  credential and a **separate** `httpx.Client`, which is what `tools-list-connection-independent`
  needs.
- New wrappers: `prompts_get()`, `tools_call_raw()`, and `notify()` (an `id`-less request).
- `Probe.build()` override set extends to `omit_client_capabilities`, `client_capabilities`,
  `omit_protocol_version_header`, `protocol_version_header`, and `origin`.

### 4.3 Concurrency

`run_scan` is a sequential loop. Rules are independent by construction — each builds its own
requests and asserts on its own responses — so they parallelise cleanly.

`run_scan(..., concurrency: int = 8)` runs rules in a thread pool, each rule receiving its **own**
`Probe` so no two rules share an `httpx.Client`. Rules that must not run concurrently with others
(the rate-limit probe of §6.5, which deliberately floods) declare `exclusive = True` and are run
alone, after the pool drains. Wall-clock for a remote target drops from *sum of per-rule latency* to
roughly *slowest rule*, which for a 70-rule catalog against a server 100 ms away is the difference
between 7 s and under 1 s.

Determinism of the *report* is preserved: findings are re-sorted by rule id before rendering, so two
runs of the same catalog against the same server produce byte-identical output regardless of
completion order.

### 4.4 Report schema v2

`json_report.render` moves to `schemaVersion: 2`, additive over v1:

- `findings[].fingerprint` — the stable identity from §7.2
- `findings[].evidenceKey` — the per-rule stable key the fingerprint is built from
- `findings[].verifiedBy` — `"black_box"` or the gray-box evidence kind that settled it (§5)
- `findings[].waivedBy` — the waiver that suppressed it, with its expiry
- `rules[]` — the catalog as evaluated, with `introduced_in` / `deprecated_in`, so an old report
  stays interpretable
- `policy` — the resolved configuration, with each value's source (CLI / env / file / default)
- `target` — `{endpoint, name, manifestHash}` rather than a bare endpoint string

v1 remains emittable via `--schema-version 1` for one minor release.

---

## 5. Gray-box evidence — discharging `INDETERMINATE`

This is the feature no competitor has, and it follows directly from the honesty the project already
practises. The README already names, for each of the five unverifiable MUSTs, exactly what evidence
would settle it. v1 accepts that evidence.

### 5.1 The contract

An `UNVERIFIABLE` rule keeps `check(probe) -> INDETERMINATE` and gains an optional second entry
point:

```python
graybox_evaluate(probe: Probe, evidence: Evidence) -> RuleResult
```

`BaseRule.evaluate` calls `graybox_evaluate` only when the rule's declared `evidence_kind` is
present in the supplied `Evidence`; otherwise it falls through to `check` and returns
`INDETERMINATE` exactly as today. **Absence of evidence never becomes a pass.** The coercion in
`BaseRule.evaluate` that forces `UNVERIFIABLE` rules to `INDETERMINATE` is relaxed only along this
one path, and only when evidence is actually present — and the resulting `RuleResult` records
`verified_by` naming the evidence, so a reader can check the claim rather than trust it.

### 5.2 The five kinds

| Rule | Evidence kind | What the operator supplies | Verdict logic |
|---|---|---|---|
| `token-audience-validated` | `wrong_audience_token` | A token signed by the server's own issuer with a different `aud` | Present it. A served request is a FAIL. A refusal that is *also* how the server refuses a garbage token is `INDETERMINATE` — indistinguishable is not the same as correct, so a control token with a bad signature is sent too, and the two refusals must differ. |
| `no-token-passthrough` | `egress_capture` | A command or file yielding the server's outbound requests during the scan window | Call an authenticated tool with a uniquely-marked token; FAIL if the mark appears in egress. |
| `handle-possession-is-not-authentication` | `second_principal` | A second principal's token | Mint a handle as A, present it as B. Served → FAIL. |
| `mrtr-retries-are-idempotent` | `effect_counter` | A command or URL returning a monotonic count of the effect **at its source** | Read, run an MRTR flow to completion, retry the consumed flow, read again. Delta > 1 → FAIL. Counting in the reply is what the README says proves nothing, so the counter must be external. |
| `invocations-are-audited` | `audit_verify` | A command that verifies the log and prints a count | Count before, invoke *n* tools, count after, and require the verifier to exit 0. Delta ≠ *n* → FAIL. |

For the broker these map onto capabilities that already exist — `broker audit verify` is the
`audit_verify` command, and `deployment_attempts` is the `effect_counter` source. That is deliberate:
the reference application should be able to demonstrate the gray-box path end to end, which is what
turns "we support this" into a demo.

### 5.3 Safety

Gray-box evidence means running operator-supplied commands. So: commands are read from the config
file only, never from a scanned server's response; they are executed with `shell=False` and an
argv list, a timeout, and a captured environment; and `--no-exec` disables every command-shaped
evidence kind, leaving only the file- and token-shaped ones. A scan against an untrusted endpoint
can never cause command execution, because no field a server controls reaches a command line.

---

## 6. Catalog expansion — 35 rules to roughly 70

New modules under `catalog/must/` and `catalog/should/`. Every rule cites a live anchor; every rule
declares `evidence_key` for fingerprinting (§7.2).

### 6.1 `must/meta.py` — required request metadata

Spec: *"A request missing any required field is malformed; the server **MUST** reject it with
JSON-RPC error code `-32602`… On HTTP, the response status **MUST** be `400 Bad Request`."*

- `missing-client-capabilities-rejected` — omit `clientCapabilities`; require `-32602` + HTTP 400
- `missing-protocol-version-rejected` — omit `_meta` `protocolVersion`; same
- `missing-capability-error-shape` — where a server emits `-32021`, `data.requiredCapabilities`
  must be a non-empty array (`NOT_APPLICABLE` when the server never emits it)

### 6.2 `must/http.py` — the HTTP layer, which no rule inspects today

- `unknown-method-http-404` — *"it **MUST** respond with `404 Not Found`"*
- `header-mismatch-http-400`, `missing-header-http-400` — tighten the existing header rules, which
  currently accept any `status >= 400` or none at all
- `protocol-version-header-required` — a distinct required header with zero coverage today
- `protocol-version-header-body-mismatch-rejected` — *"If the values do not match, the server
  **MUST** reject… with `400 Bad Request` and a `HeaderMismatch` JSON-RPC error"*
- `invalid-origin-rejected` — *"servers **MUST** respond with HTTP 403 Forbidden"* (DNS rebinding)
- `response-content-type-valid` — `application/json` or `text/event-stream`
- `get-delete-405` (SHOULD) — `405 Method Not Allowed`
- `notification-returns-202` — an `id`-less request gets `202 Accepted` with no body

### 6.3 `must/mrtr.py` — including the test the probe was built for

`HANDOFF` §9.4 designed the probe to send "a forged `requestState`", and no rule ever used it.

- `tampered-requeststate-rejected` — flip a byte in a returned `requestState` and retry;
  *"servers **MUST** treat `requestState` as attacker-controlled input… and **MUST** reject state
  that fails verification."* `NOT_APPLICABLE` if the target never returns one.
- `input-required-carries-requests-or-state` — at least one of the two
- `input-requests-shape-valid` — values restricted to `ElicitRequest` / `CreateMessageRequest` /
  `ListRootsRequest`
- `input-required-only-on-supported-requests` — *"Servers **MUST NOT** send `InputRequiredResult`
  responses on any other client requests"*
- `input-requests-respect-declared-capabilities` — with `clientCapabilities: {}` declared, a server
  must not ask for elicitation, sampling, or roots. Newly testable only because of §3.3.
- `mrtr-retry-requires-new-id` — *"the JSON-RPC `id` **MUST** be different between the initial
  request and the retry"* (checked from the server's side: a retry reusing the id must be refused)

### 6.4 `must/primitives.py` — `resources/read` and `prompts/get`

The current `LIST_ENDPOINTS` set silently excludes the three highest-traffic methods, and swaps
`resources/read` — which the changelog explicitly names as requiring `CacheableResult` — for
`server/discover`.

- `tool-call-result-type-present`, `resources-read-result-type-present`,
  `prompts-get-result-type-present`
- `resources-read-carries-ttl`, `resources-read-carries-scope`
- `resource-read-no-empty-contents-for-missing`
- `tools-capability-matches-tools-list`, and the `resources` / `prompts` variants — both directions:
  *"Servers that support tools **MUST** declare the `tools` capability"* and *"Servers that declare
  the `tools` capability **MUST** respond to `tools/list`"*
- `resource-subscribe-advertised-truthfully` — the existing truthfulness rule only checks
  `listChanged`; a server claiming `subscribe: true` slides past it entirely

### 6.5 `must/schemas.py` — the `x-mcp-header` constraint set

Six MUSTs, all readable from a single `tools/list` response, and one of them is a live header
injection:

- `x-mcp-header-not-empty`
- `x-mcp-header-token-syntax` — RFC 9110 §5.1 `1*tchar`
- `x-mcp-header-no-control-characters` — *"**MUST NOT** contain control characters, including
  carriage return (CR, `\r`) or line feed (LF, `\n`)"*
- `x-mcp-header-case-insensitively-unique`
- `x-mcp-header-primitive-types-only` — *"Parameters with type `number` are not permitted"*
- `x-mcp-header-statically-reachable`

Plus `tools-declare-valid-input-schema`, strengthening the existing presence check to *"**MUST** be
a valid JSON Schema object (not `null`)"*, and `no-retired-error-codes-emitted` — the spec names
`-32002` and `-32042` as codes this revision's implementations **MUST NOT** emit.

`tool-invocations-rate-limited` (spec: *"Servers **MUST**: … Rate limit tool invocations"*) is
`GRAY_BOX` and **opt-in** behind `--probe-rate-limit`. Flooding an endpoint you were asked to grade
is not a thing a scanner does by default; without the flag it reports `INDETERMINATE` and says why.

### 6.6 `should/naming.py`

`tool-names-well-formed` — length 1–128, the character allowlist, no spaces or commas — and
`tool-names-unique-within-server`. All SHOULD, because the spec grades every one of them SHOULD.

### 6.7 Fixtures

`fixtures/server/nonconformant.py` seeds a violation for every new black-box rule and extends
`SEEDED_VIOLATIONS`; the existing test asserting the list matches the source tags keeps the recall
denominator honest. `fixtures/server/conformant.py` implements each new requirement correctly, so
the false-positive count stays measurable and stays zero. A third fixture, `partial.py`, exercises
`NOT_APPLICABLE` paths — a server with no resources, no prompts, and no MRTR — because a rule that
has never returned `NOT_APPLICABLE` in a test has never had that branch checked.

---

## 7. Policy: configuration, waivers, baselines

Nothing in this section is novel; all of it is table stakes borrowed deliberately from tools that
already won this argument. The novelty is that no MCP tool has any of it.

### 7.1 `sentinel.toml`

Discovery: `--config`, else `./sentinel.toml`, else `./.sentinel.toml`, else none. Precedence,
narrow to wide: **CLI flag > `SENTINEL_*` env var > project config > `extends` chain > built-in
default.** Every resolved value carries its source into the report's `policy` block, and a test
asserts the full precedence matrix — because Trivy has open bugs where its own documented
precedence is not honoured, and "documented intent" is not the same as tested behaviour.

```toml
[scan]
endpoint    = "https://broker.internal/mcp"
gate        = "must"
timeout     = 10.0
concurrency = 8

[rules]
disable          = ["MCP/2026-07-28/SHOULD/get-delete-405"]
include_deprecated = false
[rules.severity]
"MCP/2026-07-28/SHOULD/tool-names-well-formed" = "must"   # stricter than spec, on purpose

[graybox]
second_principal_token_env = "SENTINEL_PRINCIPAL_B"
wrong_audience_token_env   = "SENTINEL_WRONG_AUD"
audit_verify               = ["broker", "audit", "verify", "--json"]
effect_counter             = ["psql", "-tAc", "select count(*) from deployment_attempts"]

[[waivers]]
rule       = "MCP/2026-07-28/MUST/invalid-origin-rejected"
endpoint   = "https://legacy.internal/mcp"
reason     = "Behind an ingress that strips Origin; ticket PLAT-4412"
expires_at = 2026-11-30
approved_by = "security@example.com"

extends = "sentinel-policy-acme"   # a package or a path
```

**`expires_at` is required, and a malformed value is a hard error.** Snyk's `.snyk` silently treats
a malformed date as *ignore forever*; that is the single worst failure mode available here, because
it converts an operator's typo into a permanent blind spot. A waiver past its expiry re-fails loudly
and is reported as expired, never dropped.

Severity overrides may only make a rule **stricter or disabled**, never quieter-but-still-counted:
promoting a SHOULD to MUST is a policy decision a company is entitled to make; demoting a MUST to
SHOULD to get a green gate is laundering, and the config rejects it. Disabling is allowed, because
it is visible in the report.

### 7.2 Finding fingerprints

Baselines are worthless if a finding's identity changes when nothing meaningful did. Every mature
tool fingerprints semantically — detect-secrets explicitly refuses to use line numbers "because code
is expected to move around". Sentinel's equivalent hazard is request ids, timestamps, and ephemeral
handles appearing in evidence.

```
fingerprint = sha256(rule_id ‖ target_identity ‖ evidence_key)
```

- `target_identity` is the configured target **name** when scanning a fleet, else the normalised
  endpoint (scheme + host + port + path, credentials and query stripped)
- `evidence_key` is declared **per rule** — a short, deliberately stable string. For
  `header-body-mismatch-rejected` it is the header/body pair category, not the request id. Rules
  with a single failure mode use `""`. `validate_registry` requires every rule to declare one.

### 7.3 Baselines

```bash
sentinel baseline create --endpoint … --out sentinel-baseline.json
sentinel scan --endpoint … --baseline sentinel-baseline.json --gate must
```

With a baseline, the gate fires only on fingerprints absent from it. The report always shows all
three sets — new, baselined, and **fixed** (in the baseline, now passing) — because a baseline that
only ever grows is how a tool becomes something teams route around. `sentinel baseline prune` drops
entries that now pass. A baseline records the catalog version it was taken against; scanning with a
newer catalog reports rules that did not exist at baseline time as new, and says so.

---

## 8. Beyond-spec checks

Rules that a company wants and the specification does not require get their own namespace and their
own gate, so they can never be confused with conformance:

```
SENTINEL/SECURITY/<slug>      SENTINEL/STYLE/<slug>      SENTINEL/OPS/<slug>
```

`--gate must` never considers them. `--gate security` does. v1 ships:

- `SECURITY/tool-description-injection` — imperative-instruction patterns, hidden Unicode,
  zero-width characters, and HTML comments in tool descriptions and schema `description` fields.
  Heuristic, regex-only, **no model call** — the project has no API key and will not grow one.
- `SECURITY/manifest-drift` — the snapshot/diff verdict of §9 expressed as a rule
- `SECURITY/tls-posture` — protocol version, certificate expiry, hostname match
- `SECURITY/wildcard-scopes` — `*`, `all`, `full-access` in advertised scope metadata
- `STYLE/tools-sorted-by-name` — the successor to the demoted rule in §3.2
- `OPS/latency-budget` — p95 per method against `--max-p95-ms`

Each carries the same fields as a spec rule except `citation`, which becomes `rationale` — because
a citation field pointing at nothing is exactly how a catalog starts lying.

---

## 9. Fleet and drift

### 9.1 Targets

```yaml
# sentinel-fleet.yaml
concurrency: 5
targets:
  - name: broker-prod
    endpoint: https://broker.acme.com/mcp
    token_env: BROKER_PROD_TOKEN
    gate: must
  - name: vendor-x
    endpoint: https://vendor-x.example/mcp
    token_env: VENDOR_X_TOKEN
    gate: should          # a third party you do not control
    waivers_from: vendor-x.toml
```

A target is a named, separately credentialed connection, not a bare URL — because in practice each
MCP endpoint has its own token, its own tenant, and its own acceptable gate. `sentinel scan
--targets` writes one report per target plus a rollup, and exits `1` if **any** target fails **its
own** gate. Targets are scanned concurrently up to `concurrency`; a target that is unreachable is a
harness error for that target only and never silently a pass.

### 9.2 Snapshot and diff — rug-pull detection

`SN-CAP-31`, deferred to WP-13 stretch and never built. The canonical manifest hashing already
exists, which is most of the work.

```bash
sentinel snapshot --endpoint … --out snapshots/broker-prod.json
sentinel diff snapshots/broker-prod.json --endpoint …
```

A snapshot records the canonical manifest hash, per-tool schema hashes, descriptions, scopes, and
the advertised capabilities. `diff` classifies every change by severity, because not all drift is
attack:

| Class | Example | Severity |
|---|---|---|
| `TOOL_ADDED` / `TOOL_REMOVED` | a new tool appears | info / warn |
| `SCHEMA_WIDENED` | a required argument becomes optional; an enum gains a member | warn |
| `SCHEMA_NARROWED` | a required argument is added | warn |
| `DESCRIPTION_CHANGED` | the text an LLM is steered by changed | **high** — this is the rug pull |
| `SCOPES_WIDENED` | a tool now claims more scope | **high** |
| `CAPABILITY_CHANGED` | `listChanged` flips | warn |

`diff --gate` exits `1` on any high-severity class. This is the check you run on a schedule against
a third-party MCP server you depend on and do not control, and it is the single most directly
valuable thing in v1 for a company consuming somebody else's tools.

---

## 10. Reporting and distribution

### 10.1 Formats

Existing `text`, `json`, `sarif` stay. Added:

- **`markdown`** — the PR comment and `$GITHUB_STEP_SUMMARY` target. Gate verdict and failures
  unwrapped; everything else inside `<details>`. Hard-capped under GitHub's 65,536-character comment
  limit, truncating from the least severe end and saying how much was dropped.
- **`junit`** — one `<testcase>` per rule; `INDETERMINATE` renders as `<skipped>`, never as a pass.
- **`html`** — one self-contained file, no external requests, readable offline.

SARIF gains the fingerprint as `partialFingerprints`, which is what lets GitHub code scanning track
a finding across runs instead of re-raising it.

### 10.2 Distribution

| Channel | Form |
|---|---|
| PyPI | `sentinel-mcp`, console script `sentinel`; `uvx sentinel-mcp scan …` works with no install |
| Docker | distroless, non-root, multi-arch |
| GitHub Action | **composite** — hash-pinned `setup-uv`, runs the CLI, SARIF upload left to a separate `upload-sarif` step so `security-events: write` stays scoped to it |
| GitLab CI | a template that `docker run`s the image |
| pre-commit | `.pre-commit-hooks.yaml`, for teams that scan a locally-running server |

Releases are signed with cosign keyless via GitHub OIDC, and ship a CycloneDX SBOM of the harness
itself. The README states plainly: **`sentinel` makes no network call except to the endpoint you
give it, and sends no telemetry, ever.** That costs nothing because it is already true, and it is
the cheapest trust signal available.

---

## 11. `mcp/` — the Go server kit

`broker/internal/` is where the genuinely reusable work lives, and `internal/` makes it unusable by
anyone else. v1 extracts it into a module at `github.com/patsypppe/sentinel/mcp`.

| Package | Contents | Storage |
|---|---|---|
| `mcp/envelope` | JSON-RPC envelope, the error taxonomy, `_meta`, negotiation, result finalization | — |
| `mcp/canonical` | byte-stable JSON | — |
| `mcp/registry` | `Tool` interface, deterministic manifest, token accounting | — |
| `mcp/transport` | Streamable HTTP + stdio over one dispatch pipeline, header contract, the `Authenticator` / `AuditSink` seams | — |
| `mcp/handles` | mint, resolve, GC | `handles.Store` interface |
| `mcp/mrtr` | seal/unseal, idempotent resume, sweep | `mrtr.Store` interface |
| `mcp/audit` | chain math, redaction, verification | `audit.Sink` interface |
| `mcp/authz` | audience validation, scopes, outbound credential | — |
| `mcp/postgres` | pgx implementations of the three interfaces, plus the migrations | — |

The single-source-file discipline survives the move and `CLAUDE.md` is updated to the new paths:
`mcp/envelope/errors.go`, `mcp/handles/resolve.go`, `mcp/authz/audience.go`.

Two things change beyond relocation. Storage moves behind interfaces so a company can back handles
and flows with something other than Postgres — the interfaces are extracted from what the pgx code
already does, not invented. And `mcp/` grows a `server.New(opts...)` convenience that wires the
default pipeline in one call, because a kit whose smallest working example is 200 lines of wiring is
a kit nobody adopts. `broker/cmd/broker/main.go` becomes that example.

`BROKER_OTEL_ENDPOINT` is read today and consumed by nothing. v1 either wires the OTLP exporter or
removes the key; it wires it, since the collector is already in the compose topology and trace ids
already flow into audit rows.

A `mcp/example/` minimal server — one tool, no database — is what a reader copies. `make check`
builds and scans it, so the example cannot rot.

---

## 12. `sentinel-server` — the fleet service

Go, reusing `mcp/postgres`'s migration runner and the broker's role separation.

**Ingest.** `sentinel scan --publish https://sentinel.internal` POSTs the v2 JSON report to
`POST /api/v1/scans`, authenticated with the same audience-validated bearer scheme as the broker,
reusing `mcp/authz`. The CLI never *requires* a service; `--publish` is additive, and a publish
failure is a warning, not a scan failure, because the scan's verdict is the product.

**Schema.** `targets`, `scan_runs`, `scan_findings`, `manifest_snapshots`, `waiver_ledger`. Findings
are keyed by fingerprint, which is what makes "this finding has been open for 34 days" answerable.

**Reads.** `GET /api/v1/targets`, `.../targets/{name}/posture?window=90d`,
`.../targets/{name}/drift`, `.../waivers/expiring?within=30d`, `.../fleet/summary`.

**Dashboard.** Server-rendered HTML, no SPA, no bundler, no external requests, strict CSP. Fleet
grid, per-target posture over time, drift timeline, and an expiring-waivers list. The dashboard is
a read of the API, not a second implementation of it.

**What it computes that the CLI cannot.** Time. Mean time to remediation per rule; which rules
regress most; drift events correlated across targets sharing an upstream; waivers about to expire
while their finding still fails, which is the one that actually prevents an outage.

---

## 13. Testing

Existing layers stay and extend. Added:

| Layer | Content |
|---|---|
| Precedence matrix | every config key × every source, asserting resolution order |
| Waiver expiry | boundary dates, malformed dates hard-error, expired waivers re-fail |
| Fingerprint stability | evidence containing request ids, timestamps and handles produces an identical fingerprint across runs |
| Gray-box | each of the five kinds against the broker, with evidence and without; without must stay `INDETERMINATE` |
| Concurrency | the same catalog run at concurrency 1 and 16 produces byte-identical reports |
| Citation liveness | every citation fetched in a weekly scheduled job, not in `make check` — a spec-site outage must not redden a PR |
| Rule lifecycle | a deprecated rule names a live successor; deprecated rules are excluded by default |
| Fleet | multi-target scan with one failing target exits 1; an unreachable target is a harness error for that target only |
| SDK example | `mcp/example` builds, serves, and passes `--gate must` |
| Service | ingest round-trip, posture arithmetic, drift classification |

`make check` stays fast and offline. Anything needing the network or containers is `integration` or
`e2e`, as today.

---

## 14. Work packages

One branch and one PR each, `feat/wp-N-<slug>`, `make check` green at every step.

**Phase A — correctness (§3)**

| WP | Title |
|---|---|
| **WP-14** | Rule lifecycle, the three severity corrections, deprecation-registry fidelity, probe `clientCapabilities` |
| **WP-15** | Error codes leave the legacy sub-range; broker, envelope, docs, and a rule that detects it |

**Phase B — catalog depth (§6)**

| WP | Title |
|---|---|
| **WP-16** | Probe HTTP layer + `must/meta.py` + `must/http.py` |
| **WP-17** | `must/mrtr.py` + `must/primitives.py`, `prompts/get` and `resources/read` coverage |
| **WP-18** | `must/schemas.py` (`x-mcp-header`), `should/naming.py`, the `partial` fixture |

**Phase C — product surface (§4, §5, §7, §8, §9, §10.1)**

| WP | Title |
|---|---|
| **WP-19** | `sentinel.toml`, precedence, rule toggles, severity overrides |
| **WP-20** | Fingerprints, waivers with enforced expiry, baselines |
| **WP-21** | Gray-box evidence framework and the five rules |
| **WP-22** | Rule concurrency, fleet targets, rollup |
| **WP-23** | `snapshot` / `diff` and the beyond-spec namespace |
| **WP-24** | `markdown`, `junit`, `html`, report schema v2 |

**Phase D — distribution (§10.2)**

| WP | Title |
|---|---|
| **WP-25** | PyPI, Docker, GitHub Action, GitLab template, pre-commit, cosign, SBOM |

**Phase E — the kit (§11)**

| WP | Title |
|---|---|
| **WP-26** | Extract `mcp/`, storage interfaces, `server.New`, `mcp/example`, OTel wired |

**Phase F — the service (§12)**

| WP | Title |
|---|---|
| **WP-27** | Schema, ingest, read API |
| **WP-28** | Dashboard, posture, drift, waiver-expiry |

**Phase G**

| WP | Title |
|---|---|
| **WP-29** | Measurements v2, README, migration guide, runbook, the v1 demo |

---

## 15. Definition of done

- `sentinel scan` grades ~70 rules with a live citation each; every severity matches the spec's
- The five unverifiable MUSTs return real verdicts when evidence is supplied, `INDETERMINATE` when
  it is not, and never a pass without evidence
- Recall against the non-conformant fixture stays 100% with the enlarged seeded set; false positives
  against the conformant fixture stay 0
- `sentinel scan --targets` sweeps a fleet concurrently and gates per target
- `sentinel diff` detects a description rewrite and a scope widening, and fails the gate on both
- A waiver with a malformed `expires_at` is an error; an expired waiver re-fails
- `uvx sentinel-mcp scan --endpoint …` works with no clone, and the GitHub Action runs it
- Releases are cosign-signed and carry an SBOM
- A stranger builds a conformant MCP server from `mcp/example` and it passes `--gate must`
- `sentinel-server` shows 90 days of posture and an expiring-waiver list for a fleet
- Broker emits no error code inside `-32768…-32000` that the spec did not define
- `make check` is green, offline, and under two minutes

## 16. Non-goals

Unchanged from `HANDOFF` §3.2 except where a work package names otherwise: no CIMD or consent
registry, no `subscriptions/listen`, no tasks extension, no MCP Apps. Added for v1: **no LLM
anywhere** — the tool-description injection check is regex-only, and the project acquires no model
API key; **no hosted SaaS** — `sentinel-server` is software a company runs; **no agent-behaviour
scanning** — that market is crowded and is not this tool's claim.

## 17. Risks

| Risk | Mitigation |
|---|---|
| Rule count grows faster than rule quality | every rule needs a live citation, a fixture seeding it, and an `evidence_key`; `catalog validate` enforces all three |
| The error-code migration breaks a consumer | `data.legacyCode` for one minor release, a mapping table in `MIGRATION.md`, and the change is a documented divergence rather than a silent edit |
| Extracting `mcp/` regresses the broker | the extraction is mechanical and the existing Go suite is the oracle; `make check` must stay green at every commit within WP-26 |
| Gray-box command execution becomes an attack surface | commands come only from the config file, run with `shell=False` and a timeout, and `--no-exec` disables them entirely; no server-controlled value ever reaches a command line |
| The spec moves under us | citations are checked in a scheduled job, and `SPEC_REVISION` is a single constant; a new revision is a new rule-id namespace, never an edit to the old one |
