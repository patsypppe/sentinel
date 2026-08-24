# Sentinel — Implementation Handoff

**Document ID:** SN-HND-001 · **Version:** 1.0
**Owner:** Pranav T P · **Date:** August 21, 2026
**Implements:** SN-PRD-001 §3.2 (MVP tier), Appendix C · **Gate:** AXIS G1, September 4 – September 24, 2026
**Predecessor:** Meridian (MD-HND-001), AXIS G0, completing September 4
**Spec baseline:** [Model Context Protocol `2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28/changelog)

---

## 0. How to use this document

Same working method as Meridian. Drop `CLAUDE.md` at the repo root, this file at `docs/HANDOFF.md`, and `SN-PRD-001` at `docs/PRD.md`. Work one package at a time from `PROMPTS.md`, and run the acceptance commands yourself.

**Two things are different this time, and both matter.**

First, **this project has an external source of truth.** Meridian's correctness was defined by this document. Sentinel's is defined by [the MCP specification](https://modelcontextprotocol.io/specification/2026-07-28/), and where this handoff and the spec disagree, **the spec wins and this document is wrong**. Every conformance rule cites a spec section; if you cannot cite one, the rule does not belong in the catalog.

Second, **you are building two products in one repository**: a Go server (`broker`) and a Python conformance harness (`sentinel`). They are coupled deliberately — the harness's credibility comes from grading a server that is not its own, and the server's credibility comes from being graded. Keep them separable: the harness must never import server internals, and must run against any endpoint.

**Schedule note.** SN-PRD-001 Appendix C dates the MVP August 24 – September 4. That collides with Meridian's window. This handoff re-dates it to the AXIS G1 window, **September 4 – September 24** — three weeks rather than two. The extra week is not extra scope; it goes to the migration guide, registry publication, and hardening, which are what make this repository useful to strangers rather than merely correct.

---

## 1. What you are building, in one paragraph

On **July 28, 2026** the Model Context Protocol shipped the largest breaking revision in its history: it converted MCP from a stateful, session-based, bidirectional protocol into a **stateless request/response protocol**. Sessions are gone. The `initialize` handshake is gone. `server/discover` is mandatory. Server-initiated requests were replaced wholesale by Multi Round-Trip Requests. `CacheableResult` became required. Sampling, Roots, Logging, HTTP+SSE transport, and OAuth Dynamic Client Registration were all deprecated on a twelve-month clock. Every MCP server in the wild — and every tutorial, blog post, and portfolio project — was written against the old idioms.

Sentinel is two things sold together. **Broker** is a production MCP server built natively on the new specification for a domain where state genuinely matters. **Sentinel Conformance** is a harness that scans any MCP server, grades it against the normative requirements, inventories which deprecated features it still depends on, and generates a migration plan. The harness is what makes the server credible and vice versa.

---

## 2. The four rules

### Rule 1 — Stateless. Handles are data, never credentials.

There is no session. Nothing keyed by connection. `tools/list`, `resources/list`, and `prompts/list` do not vary per connection. Cross-call state exists only as **server-minted handles passed as ordinary tool arguments**, and the spec is explicit that *possession of a handle is not authentication*: every resolution re-verifies principal and tenant against the validated token.

The temptation is an in-memory map keyed by something connection-shaped, "just for the query results". That is precisely the design the specification removed. If you find yourself writing it, stop.

### Rule 2 — No server-initiated requests. MRTR only, and it must be idempotent.

The server never calls the client. When a tool needs a confirmation, an approval, or additional input, it returns a result with `resultType: "input_required"` and an `inputRequests` array. **The client then retries the original request** — as a new JSON-RPC request with a new id — carrying `inputResponses`. Correlation happens through an identifier the server seals into `requestState`, never through the JSON-RPC id.

Because retries are client-driven, they will be duplicated. A duplicate retry of a consumed flow must return the recorded result verbatim and perform **zero** additional side effects. This is the single hardest correctness property in the project and the one worth demoing.

### Rule 3 — Deterministic where the spec asks for determinism

`tools/list` **SHOULD** return tools in deterministic order, explicitly so clients can cache and so LLM prompt-cache hit rates improve. `CacheableResult` requires `ttlMs` and `cacheScope` on every list and read result. `Mcp-Method` and `Mcp-Name` headers are **required** on Streamable HTTP POST so gateways and WAFs can route and authorize without parsing the body.

Determinism here is measurable, so measure it: 100 consecutive `tools/list` calls must produce one distinct SHA-256. A manifest that reorders under reload silently destroys every downstream client's cache.

### Rule 4 — Every invocation is audited, and no token is trusted that was not issued for this server

The specification is unambiguous: *"MCP servers MUST NOT accept any token not explicitly issued for the MCP server."* Validate the audience. Never forward an inbound token downstream — downstream calls use the server's own credential.

Every tool invocation writes an append-only, hash-chained audit row recording principal, scopes exercised, tool, redacted arguments, protocol version, trace ID, and outcome. The audit write **fails the invocation** if it fails. An unauditable action does not happen.

**Never cut, under any schedule pressure:** `resultType` and `serverInfo` on every result, handle binding, MRTR idempotency, the audit row, and the non-conformant fixture server. Those five are the product.

---

## 3. Scope

### 3.1 In scope — build these

Exactly the MVP set from SN-PRD-001 Appendix C.

| Capability | Name | Functional requirements |
|---|---|---|
| `SN-CAP-01` | Discovery and negotiation | `SN-FR-01`, `SN-FR-02` |
| `SN-CAP-02` | Request/result envelope | `SN-FR-03`, `SN-FR-04` |
| `SN-CAP-03` | Error taxonomy | `SN-FR-05` |
| `SN-CAP-05` | Header contract and gateway routing | `SN-FR-07` |
| `SN-CAP-07` | Server-minted state handles | `SN-FR-08` |
| `SN-CAP-09` | MRTR input-required flows | `SN-FR-10` |
| `SN-CAP-10` | Retry correlation and idempotency | `SN-FR-11`, `SN-FR-12` |
| `SN-CAP-11` | Cacheable results and ordering | `SN-FR-14` |
| `SN-CAP-12` | Tool design discipline | `SN-FR-15`, `SN-FR-16`, `SN-FR-17` |
| `SN-CAP-14` | Warehouse query tools | `SN-FR-20` |
| `SN-CAP-21` | Audience validation | `SN-FR-28` |
| `SN-CAP-25` | Immutable audit log | `SN-FR-32`, `SN-FR-33` |
| `SN-CAP-27` | Rule catalog and fixtures | `SN-FR-35`, `SN-FR-40` |
| `SN-CAP-28` | Grading, report output, CI | `SN-FR-37` |
| `SN-CAP-29` | Deprecation inventory | `SN-FR-38` |

### 3.2 Out of scope — do not build these

| Excluded | Why, and when it returns |
|---|---|
| **Full OAuth: CIMD registration, consent registry, scope step-up** (`SN-CAP-17`, `19`, `20`) | Audience validation (`SN-CAP-21`) is the security property that actually matters for the demo and is a MUST. The rest is a week of OAuth plumbing that demonstrates less. Demo with a static issuer and a locally-minted token. Returns in v1. |
| **SSRF containment** (`SN-CAP-22`) | Only reachable through OAuth metadata discovery, which is out. Write the egress-proxy Compose service anyway so the topology is honest, and document the gap. |
| **`subscriptions/listen`** (`SN-CAP-04`) | A long-lived stream is a meaningful amount of work for a capability nothing in the demo consumes. Advertise `listChanged: false` and be truthful about it rather than advertising a capability you do not implement — a server that lies in `server/discover` fails its own harness. |
| **Tasks extension** (`SN-CAP-06`) | Long-running operations matter when Continuum exists (AXIS G3). Until then no client polls. |
| **MCP Apps / UI resources** (`SN-CAP-16`) | v2. |
| **Rate limiting, tenant isolation enforcement, manifest signing** (`SN-CAP-23`, `24`, `26`) | Keep `tenant_id` columns and the multi-tenant schema; do not build enforcement. Single tenant, two principals — that is enough to prove handle binding. |
| **Migration plan generator, snapshot diffing** (`SN-CAP-30`, `SN-CAP-31`) | Stretch (WP-13). The *deprecation inventory* is in scope and is 80% of the value; the ordered plan is presentation on top of it. |

### 3.3 One deliberate divergence from the PRD, recorded

SN-PRD-001 §7.4 configures `handles.default_ttl`, `mrtr.flow_ttl`, and `cache.tools_list_ttl_ms`. This handoff adds one MVP-only key, **`mrtr.replay_window`**, distinct from `flow_ttl`: `flow_ttl` bounds how long a flow may sit *awaiting input*, while `replay_window` bounds how long a *consumed* flow retains its recorded result for idempotent replay. Collapsing them into one value forces a choice between a short approval window and a long replay guarantee, and you want a short window with a long guarantee. Fold this back into the PRD.

### 3.4 The one thing that must exist at the end

Two scans, side by side: the non-conformant fixture failing 20+ MUST rules with spec citations, and Broker passing with zero. Plus a deprecation inventory naming the five deprecated features with their removal dates. That pair of terminal outputs is the artifact.

---

## 4. Prerequisites

| Requirement | Version | Check |
|---|---|---|
| Go | 1.23+ | `go version` |
| Python | 3.12.x | `python3 --version` |
| uv | ≥ 0.5 | `uv --version` |
| Docker Desktop | ≥ 4.30 | `docker version` |
| Postgres 17 | via Compose | |
| Envoy | via Compose (`envoyproxy/envoy:v1.31-latest` or newer) | |
| `golangci-lint` | ≥ 1.60 | |

**No model API key is required anywhere in this project.** Broker serves tools; it does not call models. That is worth noticing — it means CI is fast, free, and never flaky for a reason outside your control.

**Read before WP-1**, in this order and in full: the [`2026-07-28` changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog), the [security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices), and the [MRTR pattern page](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr). Budget two hours. Everything downstream is cheaper if you do this first, and the conformance rule catalog is unwritable without it.

---

## 5. Repository layout

```
sentinel/
├── CLAUDE.md
├── README.md
├── MEASUREMENTS.md                     # regenerated by `make measure`
├── Makefile
├── docker-compose.yml                  # envoy + broker + postgres + smokescreen + otel
├── docs/
│   ├── HANDOFF.md                      # this document
│   ├── PRD.md                          # SN-PRD-001
│   ├── MIGRATION.md                    # "what changed in 2026-07-28 and what it costs you"
│   └── runbook.md
├── broker/                             # the Go server
│   ├── go.mod
│   ├── cmd/broker/main.go
│   └── internal/
│       ├── envelope/                   # _meta parsing, resultType, serverInfo, negotiation
│       │   ├── meta.go
│       │   ├── negotiate.go
│       │   └── errors.go               # the error-code allocation, one place
│       ├── transport/
│       │   ├── http.go                 # Streamable HTTP POST, header contract
│       │   └── stdio.go                # stdio + discover-as-compat-probe
│       ├── registry/
│       │   ├── registry.go             # tool registration interface
│       │   ├── manifest.go             # deterministic ordering + canonical hash
│       │   └── tokens.go               # manifest token accounting
│       ├── tools/
│       │   ├── warehouse/              # warehouse.query, warehouse.describe
│       │   └── ops/                    # ops.deployment_plan, ops.deployment_apply
│       ├── handles/
│       │   ├── mint.go
│       │   ├── resolve.go              # binding verification — security-critical
│       │   └── gc.go
│       ├── mrtr/
│       │   ├── engine.go               # state machine
│       │   ├── state.go                # sealed requestState (AEAD)
│       │   └── idempotency.go          # arguments_hash, recorded_result replay
│       ├── authz/
│       │   ├── audience.go             # the MUST NOT of token passthrough
│       │   └── scopes.go
│       ├── audit/
│       │   ├── writer.go               # hash chain, fail-closed
│       │   └── chain.go
│       ├── store/                      # pgx queries, migrations
│       └── telemetry/                  # OTel, traceparent from _meta
├── harness/                            # the Python conformance CLI
│   ├── pyproject.toml
│   └── src/sentinel/
│       ├── cli.py
│       ├── probe/
│       │   ├── client.py               # a deliberately literal MCP client
│       │   └── transport.py
│       ├── catalog/
│       │   ├── base.py                 # Rule, RuleOutcome, Severity, Verifiability
│       │   ├── must/                   # one module per rule group
│       │   ├── should/
│       │   └── deprecations.py
│       ├── grade.py
│       ├── report/
│       │   ├── json_report.py
│       │   ├── sarif.py
│       │   └── text.py
│       └── plan.py                     # stretch
├── fixtures/
│   └── server/                         # the non-conformant and conformant fixtures
│       ├── nonconformant.py            # deliberately violates 20+ MUSTs
│       └── conformant.py               # minimal correct server
├── envoy/
│   └── envoy.yaml
└── tests/
    ├── broker/                         # Go tests live beside the code; e2e here
    ├── harness/
    └── e2e/
```

**Layout rules.** `envelope/errors.go` is the only place error codes are defined. `handles/resolve.go` is the only place a handle becomes usable. `authz/audience.go` is the only place a token is accepted. Each is short, and a reviewer should be able to audit the security posture by reading three files.

The harness must run against a URL. It may never import from `broker/`, and a test asserts that the fixture servers — written in Python, deliberately — are the only servers the harness's own test suite uses.

---

## 6. Technology choices

| Layer | Choice | Why, and what would change it |
|---|---|---|
| Server | **Go 1.23** | It is a protocol server: concurrency, a strong stdlib HTTP stack, and a Tier 1 MCP SDK. Also the higher-signal language choice for the portfolio, and the reason this project exists in the plan. |
| JSON | `encoding/json` with **structs, never `map[string]any`**, for anything serialized deterministically | Struct field order is declaration order and therefore stable; map iteration is not. Numbers decoded into `any` become `float64` and corrupt round-trips — use `json.RawMessage` for pass-through. |
| HTTP router | stdlib `net/http` with Go 1.22+ pattern routing | One endpoint. A framework is unnecessary. |
| Database | Postgres 17 via `pgx/v5` | Handles, MRTR flows, audit chain. No ORM. |
| Migrations | `golang-migrate` | Plain SQL up/down files that a reviewer can read. |
| Crypto | stdlib `crypto/rand`, `crypto/sha256`, `golang.org/x/crypto/chacha20poly1305` | Handle IDs and the sealed `requestState`. Do not hand-roll anything else. |
| Gateway | **Envoy** | Proves the `Mcp-Method` / `Mcp-Name` header contract concretely — routing and authorization with no body parsing. |
| Harness | **Python 3.12** + `httpx` + Typer | Rule authoring should be pleasant, and rule packs are the extension point. |
| Reports | JSON + **SARIF** | SARIF renders natively in GitHub code scanning, which makes a scan a first-class CI citizen. |
| Telemetry | OpenTelemetry Go SDK | Ingest `traceparent` from `_meta` per SEP-414 and continue the client's trace. |
| Lint | `golangci-lint`, `ruff` | |

Do not add: a web framework, an ORM, a JSON-RPC library that hides the envelope (you need control of `_meta` and `resultType`), or a second database.

---

## 7. Domain model

### 7.1 The envelope

Every request carries protocol metadata in `_meta`; every result carries `resultType` and echoes `serverInfo`.

```go
// broker/internal/envelope/meta.go
const (
    KeyProtocolVersion   = "io.modelcontextprotocol/protocolVersion"
    KeyClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
    KeyClientInfo        = "io.modelcontextprotocol/clientInfo"
    KeyServerInfo        = "io.modelcontextprotocol/serverInfo"
    KeyLogLevel          = "io.modelcontextprotocol/logLevel"
    KeyTraceparent       = "traceparent"
    KeyTracestate        = "tracestate"
    KeyBaggage           = "baggage"
)

type RequestMeta struct {
    ProtocolVersion    string          `json:"io.modelcontextprotocol/protocolVersion"`
    ClientCapabilities json.RawMessage `json:"io.modelcontextprotocol/clientCapabilities,omitempty"`
    ClientInfo         *Info           `json:"io.modelcontextprotocol/clientInfo,omitempty"`
    LogLevel           string          `json:"io.modelcontextprotocol/logLevel,omitempty"`
    Traceparent        string          `json:"traceparent,omitempty"`
}

type ResultType string
const (
    ResultComplete      ResultType = "complete"
    ResultInputRequired ResultType = "input_required"
)
```

**Two rules with teeth.** Every result struct embeds `ResultType` and it is never the zero value — add a serialization test that marshals every result type and asserts the field is present and non-empty. And a result from an earlier-protocol server that omits `resultType` is treated as `"complete"`; the harness needs this to scan legacy servers without crashing.

### 7.2 Error taxonomy

The `2026-07-28` allocation policy partitions the JSON-RPC server-error range. Implement it exactly, in one file.

| Code | Name | When |
|---|---|---|
| `-32602` | Invalid Params | Includes **resource not found** — moved from `-32002` in this revision |
| `-32020` | `HeaderMismatch` | `Mcp-Method` or `Mcp-Name` disagrees with the JSON-RPC body |
| `-32021` | `MissingRequiredClientCapability` | The operation needs a capability the client did not declare |
| `-32022` | `UnsupportedProtocolVersion` | Negotiation failure |
| `-32000` … `-32019` | Implementation-defined | Sentinel's own: handle not resolvable, MRTR flow expired, retry arguments mutated, budget exceeded |

Reserve `-32020` … `-32099` for the specification and never allocate inside it. Write a test that enumerates every error the server can emit and asserts none falls in the reserved range.

### 7.3 Tool registration

A tool cannot exist without declaring all six properties. Enforce it in the interface, not in a review checklist.

```go
// broker/internal/registry/registry.go
type Tool interface {
    Name() string                    // namespaced: "warehouse.query"
    InputSchema() json.RawMessage    // JSON Schema 2020-12
    OutputSchema() json.RawMessage
    Scopes() []string                // required scopes
    Reversibility() Reversibility    // Reversible | Recoverable | Irreversible
    CachePolicy() CachePolicy        // ttlMs + scope for results
    TokenCap() int                   // hard cap on response tokens
    Call(ctx context.Context, p Principal, args json.RawMessage) (Result, error)
}
```

`Reversibility` drives whether a call requires MRTR confirmation: `Irreversible` always does; `Recoverable` does above a configured threshold; `Reversible` never does. This is OpenAI's tool-safeguard taxonomy — risk rated by reversibility and financial impact — and putting it in the type system means a new tool cannot skip the question.

### 7.4 Handles

```go
type Handle struct {
    ID          string    // "hnd_" + base32(CSPRNG 128 bits)
    TenantID    uuid.UUID
    PrincipalID uuid.UUID
    Binding     string    // "<principal_id>:<handle_id>" — verified on every use
    Kind        string    // query_result | deployment_plan | upload
    Payload     json.RawMessage
    ExpiresAt   time.Time
    RevokedAt   *time.Time
}
```

Resolution is a single query and there is exactly one correct shape for it:

```sql
SELECT payload FROM state_handles
 WHERE handle_id = $1
   AND tenant_id = $2
   AND principal_id = $3
   AND revoked_at IS NULL
   AND expires_at > now();
```

**Return the identical error for "does not exist" and "not yours."** Distinguishing them turns the handle space into an enumeration oracle. There is a named test for this.

### 7.5 MRTR flow

```go
type FlowStatus string   // awaiting_input | consumed | expired | abandoned

type Flow struct {
    CorrelationID  string          // sealed into requestState, never the JSON-RPC id
    TenantID       uuid.UUID
    PrincipalID    uuid.UUID
    ToolName       string
    ArgumentsHash  string          // rejects a retry with mutated arguments
    InputRequests  json.RawMessage
    Status         FlowStatus
    RecordedResult json.RawMessage // replayed verbatim on duplicate retry
    ExpiresAt      time.Time
    ConsumedAt     *time.Time
}
```

`requestState` is an **AEAD-sealed** blob containing the correlation ID and expiry, keyed by a server secret. The client stores and returns it opaquely; the server unseals and verifies. A tampered or forged `requestState` is indistinguishable from garbage and is rejected — which is the point of sealing rather than encoding.

### 7.6 Database

Take `tenants`, `principals`, `state_handles`, `mrtr_flows`, `tool_invocations`, `tool_manifest_snapshots`, and `conformance_runs` verbatim from SN-PRD-001 §6.2. Defer `oauth_clients` and `consent_grants` until OAuth is in scope.

Two things are load-bearing and easy to skip:

```sql
-- The application role may only append to the audit table.
REVOKE UPDATE, DELETE, TRUNCATE ON tool_invocations FROM broker_app;
GRANT INSERT, SELECT ON tool_invocations TO broker_app;
```

`tool_invocations` is `PARTITION BY RANGE (occurred_at)`. **Automate partition creation** — a migration that creates the current and next month, plus a job that rolls forward. Inserts fail hard at a month boundary otherwise, and they fail at midnight on the first, which is exactly when nobody is looking.

---

## 8. Protocol rules, specified precisely

These are the places an agent will produce plausible code that is subtly wrong. Each has a mandatory test.

### 8.1 Version negotiation

Every request carries `io.modelcontextprotocol/protocolVersion` in `_meta`. There is no handshake to fall back on, which means negotiation happens on **every single request** and must be cheap.

| Request state | Response |
|---|---|
| Version present and supported | Proceed. Echo `io.modelcontextprotocol/serverInfo` in the result `_meta`. |
| Version present, unsupported | `-32022 UnsupportedProtocolVersion`, listing `supportedVersions` in the error data. |
| Version absent, legacy support enabled | Treat as `2025-11-25`, serve if the operation exists in that revision, and **record a `deprecated.feature_used` event**. |
| Version absent, legacy support disabled | `-32022`. |
| Operation requires a client capability not declared in `clientCapabilities` | `-32021 MissingRequiredClientCapability`, naming the capability. |

`server/discover` is the exception: it **MUST** be answerable without a negotiated version, because its entire purpose is to let a client find out what versions exist before committing. Serving `-32022` from `server/discover` is a bug that makes your server undiscoverable, and it is an easy one to write.

On stdio, `server/discover` doubles as a backward-compatibility probe: a `2025-11-25` server will not recognize the method, and the method-not-found error is itself the signal.

**Test:** a matrix test over {absent, `2025-11-25`, `2026-07-28`, `2099-01-01`, malformed} × {`server/discover`, `tools/list`, `tools/call`} asserting the exact code for each of the fifteen cells.

### 8.2 The header contract

Streamable HTTP POST requires `Mcp-Method` and `Mcp-Name`. The reason is architectural: a gateway or WAF must be able to route and authorize **without parsing the JSON body**.

Validation: `Mcp-Method` must equal the JSON-RPC `method`; `Mcp-Name` must equal the tool, prompt, or resource name where the method takes one, and the method name otherwise. Mismatch is `-32020 HeaderMismatch`.

Prove the point rather than asserting it: `envoy/envoy.yaml` routes on `Mcp-Method` and denies `tools/call` with `Mcp-Name: ops.*` from an untrusted route, with **no body parsing configured anywhere**. An integration test sends a body claiming a different method and shows Envoy routed on the header while Broker rejected the mismatch. That pair — routed by header, rejected by body check — is the demonstration.

### 8.3 Deterministic manifest and canonical hashing

```
1. Sort tools by name, byte-wise over the UTF-8 encoding. Not locale collation,
   not case-insensitive — `bytes.Compare` semantics.
2. Within each tool, emit fields in a fixed struct order.
3. Sort every `required` array and every `enum` array.
4. Serialize with no insignificant whitespace.
5. manifest_hash = "sha256:" + hex(sha256(bytes))
```

Every list result carries `CacheableResult`:

```json
{
  "resultType": "complete",
  "tools": [ ... ],
  "ttlMs": 300000,
  "cacheScope": "private"
}
```

Choose `cacheScope` deliberately per endpoint and say why in a comment: `tools/list` is `private` when the visible tool set varies by principal's scopes and `public` only if it genuinely does not. Getting this wrong lets a shared intermediary serve one tenant's tool list to another.

**Test `test_tools_list_is_byte_stable`:** call `tools/list` 100 times, hash each response body, assert exactly one distinct hash. Then reload the registry and assert the hash is unchanged. Registry reload is where determinism usually dies, because a map got iterated somewhere.

**Token accounting.** `registry/tokens.go` counts tokens of the serialized manifest with a named tokenizer and a stated method, and `make measure` writes before/after numbers into `MEASUREMENTS.md`. Anthropic's guidance is the reference point: agents wired to many tools "need to process hundreds of thousands of tokens before reading a request," and consolidating tool surfaces is how that is fixed. Your number should show the effect of namespacing and consolidating your own tools, honestly measured.

### 8.4 Tool response discipline

Three mechanisms, all from `SN-CAP-12`:

- **`response_format: concise | detailed`** as a standard argument on every tool that can return variable-size output. Anthropic measured a Slack response dropping from 206 to 72 tokens with this one change; report your own equivalent per tool.
- **A hard token cap** per tool (`TokenCap()`), defaulting to the configured 25,000. Exceeding it does not truncate silently: the tool returns a **handle** to the full result plus a summary, which is exactly what handles are for.
- **Actionable errors.** `"invalid argument"` is a bug. `"'since' must be ISO-8601; got '2026/09/01'; try '2026-09-01'"` is the standard. The model reads these and retries on them, so they are part of the tool's interface.

### 8.5 The MRTR state machine

This is the heart of the project. Draw it before coding it.

```
                    tools/call (Irreversible tool)
                              │
                              ▼
                    ┌──────────────────┐
                    │ awaiting_input   │──── expires_at reached ──▶ expired
                    │ requestState     │
                    │ sealed → client  │──── never retried ───────▶ abandoned (GC)
                    └────────┬─────────┘
                             │ retry with inputResponses + requestState
                             ▼
                  ┌──────────────────────┐
                  │ verify seal          │  tampered → -3200x
                  │ verify arguments_hash│  mutated  → -3200x
                  │ verify principal     │  mismatch → -3200x
                  └──────────┬───────────┘
                             │ first time
                             ▼
                    ┌──────────────────┐
                    │ execute effect   │  ← the ONLY place a side effect happens
                    │ record result    │
                    │ status=consumed  │
                    └────────┬─────────┘
                             │
      duplicate retry ───────┴──────▶ return RecordedResult verbatim, zero effects
      (within replay_window)
```

Rules that must hold, each as a named test:

| Property | Test |
|---|---|
| A retry arrives as a **new JSON-RPC request with a new id**; correlation is via sealed `requestState` only | `TestCorrelationIgnoresRequestID` |
| A tampered `requestState` is rejected | `TestTamperedRequestStateRejected` |
| A retry whose arguments differ from the original is rejected, not silently honored | `TestMutatedArgumentsRejected` |
| A retry from a different principal is rejected | `TestCrossPrincipalRetryRejected` |
| A duplicate retry returns the recorded result and causes **zero** additional side effects | `TestDuplicateRetryIsIdempotent` |
| A retry after `flow_ttl` returns an expired error instructing the client to restart | `TestExpiredFlowRejected` |
| A retry after `replay_window` but before GC returns a clear "result no longer available" error, never a re-execution | `TestReplayWindowExpiry` |

`TestDuplicateRetryIsIdempotent` should count side effects by asserting on a table row count or a call counter, not by inspecting the response. The response looking right while the effect happened twice is the exact failure this test exists to catch.

**Sealing.** `requestState = base64(nonce || AEAD(key, nonce, correlation_id||expiry, aad=tool_name))`. Binding the tool name as additional authenticated data means a sealed state for one tool cannot be replayed against another.

### 8.6 Audience validation and the passthrough ban

```go
// broker/internal/authz/audience.go — the only place a token is accepted
func Validate(tok string, cfg Config) (Principal, error) {
    claims, err := verifySignature(tok, cfg.JWKS)
    if err != nil { return Principal{}, ErrUnauthenticated }
    if !containsExact(claims.Audience, cfg.Audience) {
        return Principal{}, ErrWrongAudience     // MUST NOT accept
    }
    if claims.Issuer != cfg.Issuer { return Principal{}, ErrWrongIssuer }
    if claims.ExpiresAt.Before(time.Now()) { return Principal{}, ErrExpired }
    return principalFrom(claims), nil
}
```

Two tests, both negative, both required:

- `TestTokenForAnotherAudienceRejected` — a structurally valid, correctly signed token whose `aud` names a different service is rejected. This is the specification's explicit MUST NOT.
- `TestInboundTokenNeverForwarded` — capture every outbound request the broker makes while serving a call, and assert the inbound token string appears in none of them. Downstream calls use the broker's own credential.

The second test is the one that actually catches the bug, because forwarding a token feels helpful when you write it.

### 8.7 Audit hash chain

```
row_hash = sha256(prev_hash || canonical_json(auditable_fields))
```

Per-tenant chain. The first row's `prev_hash` is 64 zeros. `canonical_json` sorts keys, uses no insignificant whitespace, and contains **no floats** — durations are integer milliseconds.

Ordering rule: the audit row is committed **in the same transaction as the side effect** where the effect is a database write, and **before the response is written** otherwise. If the audit write fails, the invocation fails. Fail closed.

Verification: `broker audit verify --from --to` walks the chain and reports the first break. Test `TestChainDetectsTampering` mutates a row via a superuser connection and asserts verification points at exactly that row.

### 8.8 The conformance rule model

```python
# harness/src/sentinel/catalog/base.py
class Severity(StrEnum):     MUST = "must"; SHOULD = "should"; MAY = "may"
class Verifiability(StrEnum):
    BLACK_BOX = "black_box"          # provable from the wire alone
    GRAY_BOX = "gray_box"            # needs cooperative configuration
    UNVERIFIABLE = "unverifiable"    # cannot be proven externally

class Outcome(StrEnum):
    PASS = "pass"; FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    INDETERMINATE = "indeterminate"  # verifiability prevented a verdict

class Rule(Protocol):
    id: str                # "MCP/2026-07-28/MUST/discover-implemented"
    severity: Severity
    citation: str          # URL with anchor into the spec — mandatory
    verifiability: Verifiability
    remediation: str       # what to change, not what is wrong
    fixtures: list[str]    # which fixture profiles exercise it
    async def evaluate(self, probe: Probe) -> RuleResult: ...
```

**`INDETERMINATE` is not optional and not a weakness.** Several MUSTs — "MUST NOT accept a token not issued for this server", "MUST NOT treat handle possession as authentication" — cannot be proven black-box against an arbitrary server. A harness that silently scores them as passes is lying. Report them in their own bucket, exclude them from the gate, and list them in the README under "limitations, including which MUSTs are unverifiable black-box." Saying so is the credibility move; papering over it is the thing a reviewer will catch.

**Grading and the exit-code contract.** `sentinel scan --gate must` exits `1` if any MUST rule returns FAIL, and `0` otherwise. INDETERMINATE never fails a gate but is always printed. Every other subcommand reserves non-zero for harness errors — same discipline as Meridian's `meridian gate`, and for the same reason: CI must distinguish "the server is wrong" from "the scanner broke."

**Rule IDs are permanent.** Once published, a rule ID never changes meaning. Deprecate and add rather than redefine, or every historical report becomes uninterpretable.

**The mechanism now exists, and it has been used.** `BaseRule` carries `introduced_in`, `deprecated_in`, `superseded_by` and `rationale`; `Registry.all()` excludes deprecated rules unless asked; `validate_registry` requires every deprecated rule to name a successor that exists, and permits a deprecated rule and its successor to share a slug — which is the whole point. `sentinel scan --include-deprecated-rules` runs them anyway, so a report written before a correction can be reproduced. Rule IDs also gained a second namespace: `SENTINEL/<CATEGORY>/<slug>` for rules this project believes in that the specification does not require. A `SENTINEL` rule carries a `rationale` **instead of** a `citation` — a citation pointing at nothing is how a catalog starts lying — and can never fail a spec gate, because a beyond-spec finding that failed `--gate must` would make a conformance verdict unfalsifiable.

Three rules were corrected in **0.2.0**, each because it demanded more than the specification does: `MCP/2026-07-28/MUST/server-info-echoed` → `MCP/2026-07-28/SHOULD/server-info-echoed` (`serverInfo` is *Required: No*); `MCP/2026-07-28/MUST/tools-list-is-deterministic` → `MCP/2026-07-28/SHOULD/tools-list-is-deterministic` (deterministic ordering is a SHOULD; the MUST in that paragraph is that the set not vary per-connection, which is now `MCP/2026-07-28/MUST/tools-list-connection-independent` and needs two connections to see); and `MCP/2026-07-28/SHOULD/tools-sorted-by-name` → `SENTINEL/STYLE/tools-sorted-by-name` (the spec asks for a deterministic order, never a sorted one). The non-conformant fixture still violates all three and seeds them under their successor IDs, so recall is reported per severity rather than improved by dropping them.

---

## 9. Component specifications

### 9.1 Transport and envelope layer

One HTTP endpoint, `POST /mcp`. In order: validate headers (§8.2) → parse the envelope → negotiate the version (§8.1) → authenticate and validate audience (§8.6) → dispatch → attach `resultType` and `serverInfo` → write the audit row (§8.7) → respond.

Attaching `resultType` and `serverInfo` happens in **one middleware**, not per handler. A handler that constructs its own response envelope will eventually forget a field, and the harness will catch it in public.

stdio transport is a thin adapter over the same dispatch path — the same code must satisfy both, which is a useful forcing function against transport-specific state.

**Removed methods must return method-not-found, not silence:** `ping`, `logging/setLevel`, `notifications/roots/list_changed`, `resources/subscribe`, and `resources/unsubscribe` are gone in this revision. A conformance rule checks exactly this, so your server must satisfy its own harness.

### 9.2 Tool registry

Registration is compile-time via the `Tool` interface (§7.3). At start, the registry builds the manifest once, computes its hash and token count, and logs both. `tools/list` serves the precomputed bytes — do not re-serialize per request, both because it is wasteful and because re-serialization is where determinism dies.

Registry reload bumps a manifest version and, when `subscriptions/listen` eventually exists, emits `tools.list_changed`. For the MVP, advertise `listChanged: false` and be honest.

### 9.3 The tool domain

`warehouse.query` is the MVP tool and it is chosen carefully: it produces variably-sized output, which forces handles; it has real permissions, which forces scopes; and it is read-only, which keeps MRTR out of the MVP critical path until `ops.deployment_apply` arrives.

| Tool | Reversibility | Behavior |
|---|---|---|
| `warehouse.describe` | Reversible | Schema for tables visible to the principal's scopes |
| `warehouse.query` | Reversible | Scoped SQL with a row limit; over the limit returns a `query_result` handle plus a summary |
| `ops.deployment_plan` | Reversible | Produces a `deployment_plan` handle |
| `ops.deployment_apply` | **Irreversible** | Consumes a plan handle; **always** requires MRTR confirmation |

`ops.deployment_apply` exists solely to make the MRTR demo real. Its "deployment" can write rows to a table — what matters is that it is irreversible by declaration, requires confirmation by the type system rather than by remembering, and increments a counter that `TestDuplicateRetryIsIdempotent` asserts on.

**Scoped SQL, stated plainly:** the principal's scopes map to an allowlist of schemas and tables; queries are parsed and rejected if they touch anything outside it; a statement timeout and a row cap are enforced server-side. Do not attempt to make arbitrary SQL safe by string inspection — allowlist, parse, cap.

### 9.4 Harness probe

`probe/client.py` is a **deliberately literal** MCP client: it constructs requests by hand from the specification rather than using an SDK. This is the correct choice for a conformance tool, because an SDK would paper over exactly the deviations you are trying to detect — an SDK that helpfully adds `Mcp-Method` makes the rule "requires `Mcp-Method`" untestable.

The probe must be able to send deliberately malformed requests: absent `_meta`, mismatched headers, an unsupported version, a forged `requestState`. Rules need those to prove negative properties.

Per-rule timeouts, because a hung target must not hang the scan.

### 9.5 The two fixture servers

`fixtures/server/nonconformant.py` violates at least twenty MUSTs — no `server/discover`, missing `resultType`, non-deterministic `tools/list` ordering, absent `ttlMs`/`cacheScope`, server-initiated requests instead of MRTR, a `-32002` resource-not-found, an error allocated inside the reserved range, `ping` still implemented, handle possession accepted as authentication, and so on. Each violation is tagged in a comment with the rule ID it should trip.

`fixtures/server/conformant.py` is minimal and correct.

Together they are the harness's own oracle: **recall** is the fraction of seeded violations detected against the non-conformant fixture; **false-positive rate** is the count of failures reported against the conformant one, which must be zero. Both go in `MEASUREMENTS.md`. This is the same self-measurement discipline Meridian applies to itself, and for the same reason — a scanner that cannot state its own recall is asking to be trusted rather than earning it.

---

## 10. Work packages

Fourteen packages across three weeks, September 4 – 24, 2026. Do them in order; WP-1 gates everything and WP-6 is the hard one.

---

### WP-0 — Repository bootstrap · Sep 4

**Objective.** A two-language monorepo where `make check` passes on empty code.

**Files.** `go.mod` in `broker/`, `pyproject.toml` in `harness/`, root `Makefile`, `docker-compose.yml` (postgres, broker, envoy, smokescreen, otel-collector), `.golangci.yml`, `.github/workflows/ci.yml`, `docs/` seeded with this handoff and the PRD.

**Acceptance.**
```bash
make check          # golangci-lint + go test ./... + ruff + pytest -m unit
docker compose up -d postgres && docker compose ps
```

**Pitfalls.** Do not let the agent add a Go web framework, an ORM, or a JSON-RPC library. The envelope is the product; a library that owns it will fight you for three weeks.

---

### WP-1 — Envelope, discovery, negotiation, error taxonomy · Sep 5–7 · `SN-CAP-01`, `SN-CAP-02`, `SN-CAP-03` · `SN-FR-01`–`SN-FR-05`

**Read the spec changelog and the security page before this package.** Everything downstream depends on getting the envelope right.

**Objective.** A spec-derived client can call `server/discover` and receive a valid result; every result carries `resultType` and `serverInfo`; every error code is correctly allocated.

**Files.** `internal/envelope/{meta,negotiate,errors}.go`, `internal/transport/http.go`, `cmd/broker/main.go`.

**Acceptance.**
```bash
go test ./broker/internal/envelope/... -run TestNegotiation -v
curl -s localhost:8080/mcp -H 'Mcp-Method: server/discover' -H 'Mcp-Name: server/discover' \
  -d @testdata/discover.json | jq '.result.resultType, .result.supportedVersions'
```

Required tests: the fifteen-cell negotiation matrix from §8.1; `TestEveryResultCarriesResultType` (marshal every result type, assert present and non-empty); `TestNoErrorInReservedRange` (enumerate every emittable error, assert none in `-32020`…`-32099` except the three the spec defines); `TestDiscoverAnswerableWithoutNegotiatedVersion`.

**Definition of done.** `server/discover` returns supported versions, capabilities, and identity, and truthfully advertises `listChanged: false` and no extensions.

**Pitfalls.** Rejecting `server/discover` for an unsupported version — an easy and fatal bug. Using `map[string]any` anywhere in a serialized result. Forgetting that removed methods must return method-not-found rather than being silently absent from the router.

---

### WP-2 — Header contract and Envoy routing · Sep 8 · `SN-CAP-05` · `SN-FR-07`

**Objective.** `Mcp-Method` and `Mcp-Name` are required and validated against the body; Envoy routes and authorizes on headers alone.

**Files.** `internal/transport/http.go` (header validation), `envoy/envoy.yaml`, `tests/e2e/test_header_routing.py`.

**Acceptance.**
```bash
docker compose up -d envoy broker
uv run pytest tests/e2e/test_header_routing.py -v
```

Tests: a missing header is rejected; a header disagreeing with the body returns `-32020`; Envoy routes `tools/call` with `Mcp-Name: ops.*` to a restricted route and denies it from an untrusted listener — with **no body parsing anywhere in the Envoy config**, which a test asserts by grepping the config for JSON filters.

**Pitfalls.** An Envoy config error denies valid traffic silently. Add a config test to CI on day one.

---

### WP-3 — Registry, deterministic `tools/list`, `CacheableResult` · Sep 9–10 · `SN-CAP-11` · `SN-FR-14`

**Objective.** A byte-stable manifest with cache metadata, and a measured token count.

**Files.** `internal/registry/{registry,manifest,tokens}.go`.

**Acceptance.**
```bash
go test ./broker/internal/registry/... -v
make measure    # writes manifest token counts into MEASUREMENTS.md
```

Required tests: `TestToolsListByteStable` (100 calls, one distinct hash); `TestStableAcrossReload`; `TestCacheableFieldsPresent` on all five list/read endpoints; `TestSortIsBytewise` (a case pair like `Warehouse` vs `warehouse` proving it is not case-insensitive collation).

**Pitfalls.** Serializing per request instead of serving precomputed bytes. Map iteration anywhere in manifest construction. Choosing `cacheScope: public` for a tool list that varies by scope — that is a cross-tenant disclosure through a shared intermediary.

---

### WP-4 — Tool discipline and `warehouse.query` · Sep 11–12 · `SN-CAP-12`, `SN-CAP-14` · `SN-FR-15`–`SN-FR-17`, `SN-FR-20`

**Objective.** A real tool with scopes, a row cap, `response_format`, a token cap, and handle overflow.

**Files.** `internal/tools/warehouse/*.go`, seed data and migrations for the queried schema.

**Acceptance.**
```bash
go test ./broker/internal/tools/... -v
# a query over the row cap returns a handle plus a summary, not a truncated result
```

Tests: `concise` versus `detailed` token counts recorded per tool; a query touching a table outside the principal's scopes is rejected; a statement exceeding the timeout is cancelled server-side; the over-cap path returns a handle.

**Pitfalls.** Attempting to make arbitrary SQL safe by inspecting strings. Allowlist schemas and tables, parse the statement, cap rows and time.

---

### WP-5 — State handles · Sep 13–14 · `SN-CAP-07` · `SN-FR-08`

**Objective.** Handles that are data, not credentials.

**Files.** `internal/handles/{mint,resolve,gc}.go`, migration for `state_handles`.

**Acceptance.**
```bash
go test ./broker/internal/handles/... -v
```

Required tests: `TestHandleIsCSPRNG` (≥128 bits of entropy, no sequential structure); `TestCrossPrincipalHandleRefused`; `TestNonexistentAndUnauthorizedAreIndistinguishable` (identical error code and message for both — this is the enumeration-oracle defense); `TestExpiredHandleRefused`; `TestGCRemovesExpired`.

**Pitfalls.** Returning a distinguishable error for "not found" versus "not yours". Caching a resolved handle in memory and skipping the re-check on the second use.

---

### WP-6 — MRTR engine and idempotent replay · Sep 15–17 · `SN-CAP-09`, `SN-CAP-10` · `SN-FR-10`–`SN-FR-12`

**The hardest package. Budget three days and do not compress it.**

**Objective.** `input_required` flows that survive client retries with exactly-once side effects.

**Files.** `internal/mrtr/{engine,state,idempotency}.go`, migration for `mrtr_flows`, `internal/tools/ops/*.go`.

**Acceptance.**
```bash
go test ./broker/internal/mrtr/... -v
uv run pytest tests/e2e/test_mrtr.py -v
```

Every test in the §8.5 table, by name. `TestDuplicateRetryIsIdempotent` must assert on a **side-effect counter**, not on the response body.

**Definition of done.** Call `ops.deployment_apply` → `input_required` → approve → retry completes → replay the identical retry → identical response, one deployment.

**Pitfalls.** Correlating by JSON-RPC id (the retry has a new one). Encoding rather than sealing `requestState`. Forgetting to bind the tool name as AEAD additional data. Executing the effect before recording the result, so a crash between them re-executes on retry — record and effect belong in one transaction.

---

### WP-7 — Audience validation · Sep 18 · `SN-CAP-21` · `SN-FR-28`

**Objective.** The specification's explicit MUST NOT, implemented and proven.

**Files.** `internal/authz/{audience,scopes}.go`.

**Acceptance.**
```bash
go test ./broker/internal/authz/... -v
```

`TestTokenForAnotherAudienceRejected` and `TestInboundTokenNeverForwarded` are both required. The second captures all outbound requests during a served call and asserts the inbound token string appears in none.

**Pitfalls.** Accepting an audience by prefix or substring rather than exact membership. Forwarding the inbound token to the warehouse because it is convenient.

---

### WP-8 — Audit log and hash chain · Sep 19 · `SN-CAP-25` · `SN-FR-32`, `SN-FR-33`

**Objective.** An append-only, tamper-evident record of every invocation, enforced by database grants rather than by convention.

**Files.** `internal/audit/{writer,chain}.go`, migration with the `REVOKE`/`GRANT` pair and partition automation.

**Acceptance.**
```bash
go test ./broker/internal/audit/... -v
broker audit verify --from 2026-09-01 --to 2026-09-30
```

Tests: `TestAppRoleCannotUpdateOrDelete` (attempt both as `broker_app`, assert permission denied); `TestChainDetectsTampering`; `TestAuditFailureFailsInvocation`; `TestPartitionAutoCreated` (advance the clock across a month boundary and assert the insert succeeds).

**Pitfalls.** Writing the audit row after the response. Floats in the hashed fields. Forgetting partition automation — inserts fail at midnight on the first of the month.

---

### WP-9 — Harness: probe, rule catalog, fixtures · Sep 20–21 · `SN-CAP-27` · `SN-FR-35`, `SN-FR-40`

**Objective.** Twenty-five MUST rules, each with a spec citation and both fixtures.

**Files.** `harness/src/sentinel/probe/*`, `catalog/base.py`, `catalog/must/*`, `fixtures/server/{nonconformant,conformant}.py`.

**Acceptance.**
```bash
uv run sentinel catalog validate     # every rule has id, citation, severity, remediation, fixtures
uv run sentinel fixture serve --profile nonconformant &
uv run sentinel scan --endpoint http://localhost:9000/mcp --format text
```

**Definition of done.** Twenty-five MUST rules; every rule cites a spec anchor; the non-conformant fixture trips at least twenty; the conformant fixture trips zero; rules that cannot be proven black-box are marked `UNVERIFIABLE` and return `INDETERMINATE` rather than a false pass.

**Pitfalls.** Using an MCP SDK in the probe — it will normalize away the deviations you are trying to detect. Writing a rule without a citation. Scoring an unverifiable MUST as a pass.

---

### WP-10 — Harness: grading, JSON, SARIF, CI gate · Sep 22 · `SN-CAP-28` · `SN-FR-37`

**Objective.** Machine-readable output and an exit-code contract CI can rely on.

**Files.** `harness/src/sentinel/grade.py`, `report/{json_report,sarif,text}.py`, `.github/workflows/conformance.yml`.

**Acceptance.**
```bash
uv run sentinel scan --endpoint $BROKER --gate must --format sarif --out scan.sarif; echo $?   # 0
uv run sentinel scan --endpoint $FIXTURE --gate must --format sarif --out bad.sarif; echo $?   # 1
uv run pytest tests/harness/test_exit_codes.py -v
```

The SARIF must render in GitHub code scanning — upload it in CI and confirm the annotations appear.

**Pitfalls.** Letting `INDETERMINATE` fail the gate. Using a non-zero exit for a scanner error and a product verdict interchangeably.

---

### WP-11 — Deprecation inventory · Sep 23 · `SN-CAP-29` · `SN-FR-38`

**Objective.** Detect which deprecated features a target still depends on, with removal dates.

**Files.** `harness/src/sentinel/catalog/deprecations.py`.

Detect at minimum: **Roots, Sampling, Logging** (deprecated together under SEP-2577), **HTTP+SSE transport**, **OAuth Dynamic Client Registration** (in favor of CIMD), and `includeContext` values `"thisServer"` / `"allServers"`. Report each with the date first deprecated and the earliest possible removal, computed from the twelve-month minimum window — so a feature deprecated on July 28, 2026 is removable **on or after July 28, 2027**. Say "on or after"; the window is a minimum, not a schedule.

**Acceptance.**
```bash
uv run sentinel deprecations --endpoint $FIXTURE --as-of 2026-09-23
```
All five detected against the fixture, none against Broker.

---

### WP-12 — Measurements, migration guide, README, demo · Sep 24

**Objective.** The artifacts that make this useful to strangers.

**Files.** `MEASUREMENTS.md`, `docs/MIGRATION.md`, `README.md`, `docs/runbook.md`, `docs/demo/`.

**`MEASUREMENTS.md` contents**, all regenerated by `make measure`:

| Measurement | Method |
|---|---|
| Manifest token count, before and after consolidation | Named tokenizer, method stated |
| Per-tool `concise` vs `detailed` token counts | Same tokenizer |
| `tools/list` determinism | Distinct SHA-256 count across 100 calls |
| MUST recall against the non-conformant fixture | Seeded violations detected ÷ seeded |
| False positives against the conformant fixture | Must be 0 |
| Scan wall-clock | p50 and p95 |

**`docs/MIGRATION.md`** is the highest-leverage thing in the repository: *"What changed in MCP `2026-07-28`, and what it costs you."* The changelog table from §2.4 of the AXIS research, each row annotated with the concrete work required and how Sentinel Conformance detects it. This is the document that gets shared, and shared documents become referrals.

---

### WP-13 — Stretch, only if ahead

In order: (1) `sentinel snapshot` and `sentinel diff` for rug-pull detection (`SN-CAP-31`) — high value, low effort now that manifests are canonical. (2) The migration plan generator (`SN-CAP-30`). (3) `subscriptions/listen` (`SN-CAP-04`), which then lets you truthfully advertise `listChanged: true`. (4) The tasks extension (`SN-CAP-06`). (5) Publication to the MCP registry under a verified namespace.

**Do not** start CIMD or the consent registry. OAuth plumbing consumes days and demonstrates less than any item above.

---

## 11. Test strategy

| Layer | Where | Runs | Content |
|---|---|---|---|
| Go unit | beside the code | every commit | envelope, negotiation, manifest, handles, MRTR, authz, audit chain |
| Go integration | `broker/internal/**/*_integration_test.go`, build tag | every commit | Postgres-backed handle and flow behavior |
| Harness unit | `tests/harness/` | every commit | rule evaluation against recorded fixtures |
| End-to-end | `tests/e2e/` | every commit | Compose up, scan both fixtures and Broker, header routing through Envoy |

**The negative tests are the product.** Nine of them, and every one must exist: cross-principal handle refused; nonexistent and unauthorized indistinguishable; tampered `requestState` rejected; mutated retry arguments rejected; cross-principal retry rejected; duplicate retry causes zero extra effects; wrong-audience token rejected; inbound token never forwarded; audit chain tamper detected.

If you are ever short on time, cut a feature rather than one of those nine. They are what the security section of the README claims, and a claim without a test is a claim a reviewer will check.

**Self-measurement.** Recall against the non-conformant fixture and false positives against the conformant one are computed in CI and written to `MEASUREMENTS.md`. A conformance scanner that does not publish its own recall is asking to be trusted rather than earning it.

---

## 12. Continuous integration

`ci.yml` — `golangci-lint`, `go test ./...`, `ruff`, `mypy`, `pytest -m unit`, then Compose-based e2e.

`conformance.yml` — brings up Broker, runs `sentinel scan --gate must --format sarif`, uploads the SARIF to code scanning, then runs the same scan against the non-conformant fixture and asserts it **fails**. Both directions in CI, because a gate that can only pass proves nothing.

```yaml
name: conformance
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: {go-version: '1.23'}
      - uses: astral-sh/setup-uv@v5
      - run: docker compose up -d postgres broker envoy
      - run: uv run sentinel scan --endpoint http://localhost:8080/mcp
             --gate must --format sarif --out broker.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: {sarif_file: broker.sarif}
      - name: Fixture must fail
        run: |
          uv run sentinel fixture serve --profile nonconformant &
          sleep 2
          if uv run sentinel scan --endpoint http://localhost:9000/mcp --gate must; then
            echo "non-conformant fixture passed the gate — the harness is broken"; exit 1
          fi
      - run: make measure && git diff --exit-code MEASUREMENTS.md || echo "measurements changed"
```

---

## 13. Demo script

Nine steps, from SN-PRD-001 Appendix C. Record once at the end of WP-12.

1. Scan the non-conformant fixture: 20+ MUST failures, each with a spec citation.
2. Scan Broker: zero.
3. Show the deprecation inventory with removal dates.
4. Call `warehouse.query` twice and show the `concise` versus `detailed` token difference.
5. Call `ops.deployment_apply`; show `input_required`; approve; show the retry completing.
6. Replay the identical retry: one deployment, two identical responses.
7. Present a leaked handle as a different principal: refusal, plus the audit row.
8. Show the client-to-server joined trace, with `traceparent` carried in `_meta`.
9. Introduce a MUST regression in Broker and show CI failing.

Steps 1–2 and 6 are the ones that get remembered: the scanner that grades other people's servers, and exactly-once under retry.

---

## 14. Gotchas

**1. `map[string]any` anywhere in a serialized result.** Go map iteration order is randomized; your byte-stable manifest will be stable in tests and unstable in production. Structs everywhere, `json.RawMessage` for pass-through.

**2. Numbers decoded into `any` become `float64`.** Round-tripping a JSON integer through `any` can change its representation and break a hash. Use `json.RawMessage` or `json.Number`.

**3. Rejecting `server/discover` on an unsupported version.** Makes your server undiscoverable. It is the one method that must answer without negotiation.

**4. Correlating MRTR retries by JSON-RPC id.** The retry is a new request with a new id. Correlate only through the sealed `requestState`.

**5. Executing the side effect before recording the result.** A crash between the two re-executes on retry. One transaction, effect and record together.

**6. Encoding `requestState` instead of sealing it.** Base64 of JSON is client-editable. AEAD-seal it, and bind the tool name as additional authenticated data.

**7. Distinguishable errors for "handle not found" versus "handle not yours."** An enumeration oracle. Identical code, identical message.

**8. Forwarding the inbound token downstream.** The specification's explicit MUST NOT, and it feels helpful when you write it. `TestInboundTokenNeverForwarded` exists for this.

**9. Audit partition not auto-created.** Inserts fail at midnight on the first of the month. Automate creation of the current and next partition in a migration plus a rollover job.

**10. Advertising a capability you do not implement.** `listChanged: true` without `subscriptions/listen` makes your server fail its own harness — which will happen in front of an audience, since step 2 of the demo is scanning yourself.

**11. Using an MCP SDK inside the conformance probe.** An SDK that helpfully adds `Mcp-Method` makes the rule requiring `Mcp-Method` untestable. Construct requests by hand.

**12. Scoring an unverifiable MUST as a pass.** The fastest way to lose a reviewer's trust. `INDETERMINATE` exists; use it, count it separately, and list those rules in the README.

**13. Envoy config errors denying valid traffic silently.** Config test in CI from day one.

**14. Allocating an error code inside `-32020`…`-32099`.** Reserved for the specification. Your codes live in `-32000`…`-32019`, and a test enumerates them.

---

## 15. Definition of done for the MVP

Every one true on September 24, 2026.

- [ ] `make check` green: `golangci-lint`, `go test ./...`, `ruff`, `mypy`, `pytest -m unit`, e2e.
- [ ] `server/discover` answers without a negotiated version and truthfully advertises capabilities.
- [ ] Every result carries `resultType` and `serverInfo`; tested by marshalling every result type.
- [ ] The fifteen-cell negotiation matrix passes; no error code falls in the reserved range.
- [ ] `tools/list` produces exactly one distinct SHA-256 across 100 calls, and across a registry reload.
- [ ] All five list/read endpoints carry `ttlMs` and `cacheScope`.
- [ ] Envoy routes and authorizes on `Mcp-Method` / `Mcp-Name` with no body parsing in its config.
- [ ] All nine negative tests from §11 pass.
- [ ] `TestDuplicateRetryIsIdempotent` asserts on a side-effect counter and passes.
- [ ] The application database role cannot UPDATE or DELETE `tool_invocations`; `broker audit verify` detects a seeded tamper.
- [ ] 25 MUST rules, each with a spec citation; ≥20 tripped by the non-conformant fixture; 0 by the conformant one.
- [ ] Unverifiable MUSTs return `INDETERMINATE`, never a false pass, and are listed in the README.
- [ ] `sentinel scan --gate must` exits 1 on the fixture and 0 on Broker, both asserted in CI.
- [ ] SARIF uploads and renders in GitHub code scanning.
- [ ] All five deprecated features detected with removal dates stated as "on or after".
- [ ] `MEASUREMENTS.md` committed and regenerated by `make measure`.
- [ ] `docs/MIGRATION.md` published.
- [ ] No OAuth beyond audience validation, no `subscriptions/listen`, no tasks extension, no UI.

---

## 16. Cut list, in order

1. **The `ops` tool domain**, leaving `warehouse` only — but then you lose the MRTR demo, so cut this only if MRTR itself is already working and you are short on polish, never before.
2. **`MEASUREMENTS.md` beyond token counts and determinism.** Keep those two; recall and false positives can be stated in prose from a manual run.
3. **Envoy**, demonstrating the header contract with a documented `curl` instead. Weaker, but the server-side validation still holds.
4. **The SARIF report**, keeping JSON and text.
5. **stdio transport**, keeping HTTP only.

**Never cut:** `resultType` and `serverInfo` on every result, handle binding, MRTR idempotency, the audit row, and the non-conformant fixture. Those five are the product. A conformance harness with no failing fixture is a harness nobody has any reason to believe.

---

## Appendix — ID index

| ID | Name | Work package |
|---|---|---|
| `SN-CAP-01` | Discovery and negotiation | WP-1 |
| `SN-CAP-02` | Request/result envelope | WP-1 |
| `SN-CAP-03` | Error taxonomy | WP-1 |
| `SN-CAP-04` | Change notifications | WP-13 (stretch) |
| `SN-CAP-05` | Header contract and gateway routing | WP-2 |
| `SN-CAP-06` | Long-running operations | WP-13 (stretch) |
| `SN-CAP-07` | Server-minted state handles | WP-5 |
| `SN-CAP-09` | MRTR input-required flows | WP-6 |
| `SN-CAP-10` | Retry correlation and idempotency | WP-6 |
| `SN-CAP-11` | Cacheable results and ordering | WP-3 |
| `SN-CAP-12` | Tool design discipline | WP-4 |
| `SN-CAP-14` | Warehouse query tools | WP-4 |
| `SN-CAP-21` | Audience validation | WP-7 |
| `SN-CAP-25` | Immutable audit log | WP-8 |
| `SN-CAP-27` | Rule catalog and fixtures | WP-9 |
| `SN-CAP-28` | Grading, report output, CI | WP-10 |
| `SN-CAP-29` | Deprecation inventory | WP-11 |
| `SN-CAP-30` | Migration plan generator | WP-13 (stretch) |
| `SN-CAP-31` | Snapshot diffing | WP-13 (stretch) |

**Primary sources.** [MCP `2026-07-28` changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog) · [Security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices) · [Extensions overview](https://modelcontextprotocol.io/docs/extensions/overview) · [2026 roadmap](https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/) · [Anthropic, *Writing tools for agents*](https://www.anthropic.com/engineering/writing-tools-for-agents) · [Anthropic, *Code execution with MCP*](https://www.anthropic.com/engineering/code-execution-with-mcp) · [OpenAI, *A practical guide to building agents*](https://cdn.openai.com/business-guides-and-resources/a-practical-guide-to-building-agents.pdf) · [MCP-Universe](https://mcp-universe.github.io/)

---

*SN-HND-001 v1.0 — August 21, 2026. Implements SN-PRD-001 MVP tier. Superseded by the MCP specification on any question of protocol behavior, by the PRD on product intent, and by reality on schedule.*
