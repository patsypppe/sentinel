# Sentinel MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship two coupled products in one repository — `broker`, a Go MCP server built natively on the MCP `2026-07-28` stateless specification, and `sentinel`, a Python conformance harness that grades any MCP server against that specification and inventories its deprecated-feature debt.

**Architecture:** `broker` is a single-endpoint (`POST /mcp`) stateless JSON-RPC server. Cross-call state exists only as server-minted, principal-bound handles stored in Postgres; multi-step interaction uses Multi Round-Trip Requests (MRTR) with AEAD-sealed `requestState` and exactly-once replay. `sentinel` is a black-box HTTP probe with a rule catalog; it never imports broker internals and is validated against two Python fixture servers — one deliberately non-conformant, one minimal-correct — which serve as its own recall/false-positive oracle.

**Tech Stack:** Go 1.23+ (stdlib `net/http`, `encoding/json`, `pgx/v5`, `chacha20poly1305`, OpenTelemetry), Python 3.12 (`httpx`, Typer, pytest), Postgres 17, Envoy, Docker Compose, `golangci-lint`, `ruff`, `mypy`.

**Spec:** `docs/HANDOFF.md` (SN-HND-001 v1.0). On any question of protocol behavior the [MCP `2026-07-28` specification](https://modelcontextprotocol.io/specification/2026-07-28/) supersedes both this plan and the handoff.

---

## Global Constraints

Copied verbatim from the spec. Every task's requirements implicitly include this section.

- **Go 1.23+**, **Python 3.12.x**, **uv ≥ 0.5**, **Postgres 17**, **Envoy `envoyproxy/envoy:v1.31-latest` or newer**, **golangci-lint ≥ 1.60**.
- **No model API key is required anywhere in this project.** Broker serves tools; it does not call models.
- **The harness must never import server internals**, and must run against any endpoint URL. A test asserts the harness's own test suite uses only the Python fixture servers.
- `envelope/errors.go` is the **only** place error codes are defined.
- `handles/resolve.go` is the **only** place a handle becomes usable.
- `authz/audience.go` is the **only** place a token is accepted.
- **Structs, never `map[string]any`**, for anything serialized deterministically. `json.RawMessage` for pass-through.
- Error codes `-32020`…`-32099` are **reserved for the specification**. Sentinel's own codes live in `-32000`…`-32019`.
- Every result carries `resultType` and `serverInfo`; a result missing `resultType` from an earlier-protocol server is read as `"complete"`.
- `cacheScope` is chosen deliberately per endpoint with a comment stating why.
- Correlation for MRTR retries is via sealed `requestState` **only**, never the JSON-RPC id.
- `requestState = base64(nonce || AEAD(key, nonce, correlation_id||expiry, aad=tool_name))`.
- Audit `canonical_json` sorts keys, uses no insignificant whitespace, and contains **no floats** — durations are integer milliseconds.
- The audit write **fails the invocation** if it fails. Fail closed.
- `sentinel scan --gate must` exits `1` if any MUST rule FAILs, `0` otherwise. `INDETERMINATE` never fails a gate but is always printed. Every other subcommand reserves non-zero for harness errors.
- **Rule IDs are permanent.** Deprecate and add; never redefine.
- Files 200–400 lines typical, **800 max**. Functions < 50 lines.
- Conventional commit format: `<type>: <description>`.

### Never cut (§2 of the spec)

`resultType` and `serverInfo` on every result · handle binding · MRTR idempotency · the audit row · the non-conformant fixture server.

### The nine negative tests (§11 of the spec)

These are the product. If short on time, cut a feature, never one of these.

1. `TestCrossPrincipalHandleRefused`
2. `TestNonexistentAndUnauthorizedAreIndistinguishable`
3. `TestTamperedRequestStateRejected`
4. `TestMutatedArgumentsRejected`
5. `TestCrossPrincipalRetryRejected`
6. `TestDuplicateRetryIsIdempotent` (asserts on a **side-effect counter**, not the response body)
7. `TestTokenForAnotherAudienceRejected`
8. `TestInboundTokenNeverForwarded`
9. `TestChainDetectsTampering`

---

## Git workflow

The repository is its own git repo (`main` default), published at `github.com/patsypppe/sentinel`.

One branch per work package, one PR per branch, squash-free merge commits so the WP history stays legible:

| WP | Branch |
|---|---|
| WP-0 | `feat/wp-0-bootstrap` |
| WP-1 | `feat/wp-1-envelope-discovery` |
| WP-2 | `feat/wp-2-header-contract` |
| WP-3 | `feat/wp-3-registry-determinism` |
| WP-4 | `feat/wp-4-tool-discipline` |
| WP-5 | `feat/wp-5-state-handles` |
| WP-6 | `feat/wp-6-mrtr-idempotency` |
| WP-7 | `feat/wp-7-audience-validation` |
| WP-8 | `feat/wp-8-audit-chain` |
| WP-9 | `feat/wp-9-harness-catalog` |
| WP-10 | `feat/wp-10-grading-sarif` |
| WP-11 | `feat/wp-11-deprecations` |
| WP-12 | `feat/wp-12-measurements-docs` |

Each PR body states the capability IDs (`SN-CAP-nn`), functional requirement IDs (`SN-FR-nn`), the acceptance commands run, and their output.

---

## File Structure

Responsibilities are locked in here; task decomposition follows from it.

### `broker/` — the Go server

| File | Responsibility |
|---|---|
| `cmd/broker/main.go` | Wire config → store → registry → transport. Subcommands: `serve`, `audit verify`, `manifest`. |
| `internal/config/config.go` | Env-backed config incl. `handles.default_ttl`, `mrtr.flow_ttl`, **`mrtr.replay_window`**, `cache.tools_list_ttl_ms`. |
| `internal/envelope/meta.go` | `_meta` key constants, `RequestMeta`, `Info`, `ResultType`, `CacheableResult`. |
| `internal/envelope/negotiate.go` | The negotiation table of §8.1. Pure function, no I/O. |
| `internal/envelope/errors.go` | **Sole** error-code allocation. `RPCError`, constructors, reserved-range guard. |
| `internal/envelope/jsonrpc.go` | `Request`/`Response` wire types; `resultType`+`serverInfo` attachment. |
| `internal/transport/http.go` | `POST /mcp`. Header contract → parse → negotiate → authn → dispatch → envelope → audit → respond. |
| `internal/transport/stdio.go` | Thin adapter over the same dispatch path. |
| `internal/transport/dispatch.go` | Method table incl. explicit method-not-found for removed methods. |
| `internal/registry/registry.go` | `Tool` interface (six mandatory properties), registration, lookup. |
| `internal/registry/manifest.go` | Deterministic ordering, canonical serialization, `sha256:` manifest hash. |
| `internal/registry/tokens.go` | Manifest + per-tool token accounting with a named tokenizer. |
| `internal/tools/warehouse/*.go` | `warehouse.describe`, `warehouse.query`; scope allowlist, row cap, statement timeout, handle overflow. |
| `internal/tools/ops/*.go` | `ops.deployment_plan`, `ops.deployment_apply` (Irreversible → always MRTR). |
| `internal/handles/mint.go` | CSPRNG id, binding construction, insert. |
| `internal/handles/resolve.go` | **Sole** resolution path. Single query, indistinguishable errors. |
| `internal/handles/gc.go` | Expiry sweep. |
| `internal/mrtr/state.go` | AEAD seal/unseal of `requestState`, tool name as AAD. |
| `internal/mrtr/engine.go` | The state machine of §8.5. |
| `internal/mrtr/idempotency.go` | `arguments_hash`, recorded-result replay, replay-window expiry. |
| `internal/authz/audience.go` | **Sole** token acceptance. Exact-membership audience check. |
| `internal/authz/scopes.go` | Scope → schema/table allowlist mapping. |
| `internal/authz/outbound.go` | Downstream credential source. Never the inbound token. |
| `internal/audit/writer.go` | Fail-closed append, in-transaction with the effect. |
| `internal/audit/chain.go` | `canonical_json`, `row_hash`, chain walk + verify. |
| `internal/store/*.go` | pgx pool, queries, migration runner. |
| `internal/store/migrations/*.sql` | Plain SQL up/down incl. `REVOKE`/`GRANT` and partition automation. |
| `internal/telemetry/otel.go` | `traceparent` ingest from `_meta`, span emission. |

### `harness/` — the Python conformance CLI

| File | Responsibility |
|---|---|
| `src/sentinel/cli.py` | Typer app: `scan`, `catalog validate`, `deprecations`, `fixture serve`. |
| `src/sentinel/probe/transport.py` | Raw HTTP with **hand-built** headers; deliberate-malformation hooks. |
| `src/sentinel/probe/client.py` | Literal MCP client. No SDK. Per-rule timeouts. |
| `src/sentinel/catalog/base.py` | `Severity`, `Verifiability`, `Outcome`, `Rule`, `RuleResult`, registry decorator. |
| `src/sentinel/catalog/must/*.py` | 25 MUST rules, one module per group, each with a spec citation. |
| `src/sentinel/catalog/should/*.py` | SHOULD rules (ordering determinism, etc.). |
| `src/sentinel/catalog/deprecations.py` | Five deprecated features + removal dates ("on or after"). |
| `src/sentinel/grade.py` | Bucketing, gate evaluation, exit-code contract. |
| `src/sentinel/report/{json_report,sarif,text}.py` | Three renderers. |
| `src/sentinel/plan.py` | Stretch: migration plan generator. |

### `fixtures/server/`

| File | Responsibility |
|---|---|
| `nonconformant.py` | ≥20 seeded MUST violations, each tagged in a comment with the rule ID it trips. |
| `conformant.py` | Minimal correct server. Must trip zero rules. |
| `common.py` | Shared tiny HTTP scaffolding for both fixtures. |

---

## Task list

Ordering is the spec's. WP-1 gates everything; WP-6 is the hard one.

---

### Task 0 — WP-0: Repository bootstrap

**Branch:** `feat/wp-0-bootstrap`

**Files:**
- Create: `broker/go.mod`, `broker/cmd/broker/main.go`, `harness/pyproject.toml`, `harness/src/sentinel/__init__.py`, `harness/src/sentinel/cli.py`, `Makefile`, `docker-compose.yml`, `.golangci.yml`, `.github/workflows/ci.yml`, `.gitignore`, `README.md`, `docs/HANDOFF.md`, `docs/PRD.md`, `envoy/envoy.yaml`
- Test: `broker/internal/version/version_test.go`, `tests/harness/test_cli_smoke.py`

**Interfaces:**
- Produces: `make check`, `make measure`, `make up`, `make test` targets. Module path `github.com/patsypppe/sentinel/broker`. Python package `sentinel` with console script `sentinel`.

- [ ] **Step 1:** Write `broker/go.mod` (`go 1.23.0`), `.golangci.yml` (golangci-lint **v2** schema — `version: "2"`), `harness/pyproject.toml` pinning `requires-python = ">=3.12,<3.13"`.
- [ ] **Step 2:** Write a trivial failing test in each language to prove the harnesses run (`version_test.go` asserting a non-empty version string; `test_cli_smoke.py` asserting `sentinel --help` exits 0).
- [ ] **Step 3:** Run both; confirm they fail for the right reason (undefined symbol / missing console script).
- [ ] **Step 4:** Implement `version.Version` and the Typer app skeleton.
- [ ] **Step 5:** Write `Makefile` with `check` = `golangci-lint run` + `go test ./...` + `ruff check` + `mypy` + `pytest -m unit`.
- [ ] **Step 6:** Write `docker-compose.yml` with postgres, broker, envoy, smokescreen, otel-collector.
- [ ] **Step 7:** Run `make check` and `docker compose up -d postgres && docker compose ps`. Both must succeed.
- [ ] **Step 8:** Commit, push branch, open PR, merge.

**Acceptance:**
```bash
make check
docker compose up -d postgres && docker compose ps
```

**Pitfall:** Do not add a Go web framework, an ORM, or a JSON-RPC library. The envelope is the product.

---

### Task 1 — WP-1: Envelope, discovery, negotiation, error taxonomy

**Branch:** `feat/wp-1-envelope-discovery` · `SN-CAP-01`, `SN-CAP-02`, `SN-CAP-03` · `SN-FR-01`–`SN-FR-05`

**Files:**
- Create: `broker/internal/envelope/{meta,negotiate,errors,jsonrpc}.go`, `broker/internal/transport/{http,dispatch}.go`, `broker/internal/config/config.go`
- Test: `broker/internal/envelope/{negotiate_test,errors_test,jsonrpc_test}.go`, `broker/internal/transport/http_test.go`

**Interfaces:**
- Produces:
  - `envelope.Negotiate(meta RequestMeta, method string, cfg NegotiationConfig) (version string, err *RPCError)`
  - `envelope.NewRPCError(code int, message string, data any) *RPCError`
  - `envelope.CodeUnsupportedProtocolVersion = -32022`, `CodeMissingRequiredClientCapability = -32021`, `CodeHeaderMismatch = -32020`, `CodeInvalidParams = -32602`
  - `envelope.Attach(result any, serverInfo Info) (json.RawMessage, error)` — sets `resultType` and `serverInfo` in one place
  - `transport.Dispatcher` interface with `Dispatch(ctx, method string, params json.RawMessage, p authz.Principal) (any, *envelope.RPCError)`

- [ ] **Step 1:** Write the 15-cell negotiation matrix test — `{absent, 2025-11-25, 2026-07-28, 2099-01-01, malformed} × {server/discover, tools/list, tools/call}` — asserting the exact code per cell.
- [ ] **Step 2:** Run it. Expect FAIL (`Negotiate` undefined).
- [ ] **Step 3:** Implement `negotiate.go` per the §8.1 table, including the `server/discover` exemption and the `deprecated.feature_used` event on legacy fallback.
- [ ] **Step 4:** Run; expect PASS.
- [ ] **Step 5:** Write `TestNoErrorInReservedRange` enumerating every emittable error, asserting none in `-32020`…`-32099` except the three the spec defines.
- [ ] **Step 6:** Write `TestEveryResultCarriesResultType` — marshal every result type, assert the field is present and non-empty.
- [ ] **Step 7:** Write `TestDiscoverAnswerableWithoutNegotiatedVersion`.
- [ ] **Step 8:** Implement `errors.go`, `jsonrpc.go`, `meta.go`, the HTTP handler, and `server/discover` returning supported versions, capabilities (`listChanged: false`, truthfully), and identity.
- [ ] **Step 9:** Run all; run the curl acceptance.
- [ ] **Step 10:** Commit, PR, merge.

**Acceptance:**
```bash
go test ./broker/internal/envelope/... -run TestNegotiation -v
curl -s localhost:8080/mcp -H 'Mcp-Method: server/discover' -H 'Mcp-Name: server/discover' \
  -d @testdata/discover.json | jq '.result.resultType, .result.supportedVersions'
```

**Pitfalls:** Rejecting `server/discover` for an unsupported version. `map[string]any` in a serialized result. Removed methods (`ping`, `logging/setLevel`, `notifications/roots/list_changed`, `resources/subscribe`, `resources/unsubscribe`) must return method-not-found, not be silently absent.

---

### Task 2 — WP-2: Header contract and Envoy routing

**Branch:** `feat/wp-2-header-contract` · `SN-CAP-05` · `SN-FR-07`

**Files:**
- Modify: `broker/internal/transport/http.go`
- Create: `broker/internal/transport/headers.go`, `envoy/envoy.yaml`, `tests/e2e/test_header_routing.py`
- Test: `broker/internal/transport/headers_test.go`

**Interfaces:**
- Produces: `transport.ValidateHeaders(h http.Header, req jsonrpc.Request) *envelope.RPCError` returning `CodeHeaderMismatch` on disagreement.

- [ ] **Step 1:** Write `TestMissingMcpMethodRejected`, `TestMissingMcpNameRejected`, `TestHeaderBodyMismatchIsMinus32020`, `TestMcpNameIsToolNameForToolsCall`.
- [ ] **Step 2:** Run; expect FAIL.
- [ ] **Step 3:** Implement `headers.go`; wire it as the first step of the HTTP handler.
- [ ] **Step 4:** Run; expect PASS.
- [ ] **Step 5:** Write `envoy/envoy.yaml` routing on `Mcp-Method` and denying `Mcp-Name: ops.*` from the untrusted listener, with **no** body-parsing filter.
- [ ] **Step 6:** Write `tests/e2e/test_header_routing.py` incl. `test_envoy_config_parses_no_json_body`, which greps the config for JSON/body filters and asserts none.
- [ ] **Step 7:** Run the e2e suite against Compose.
- [ ] **Step 8:** Commit, PR, merge.

**Acceptance:**
```bash
docker compose up -d envoy broker
uv run pytest tests/e2e/test_header_routing.py -v
```

**Pitfall:** An Envoy config error denies valid traffic silently. The config test is in CI from day one.

---

### Task 3 — WP-3: Registry, deterministic `tools/list`, `CacheableResult`

**Branch:** `feat/wp-3-registry-determinism` · `SN-CAP-11` · `SN-FR-14`

**Files:**
- Create: `broker/internal/registry/{registry,manifest,tokens}.go`
- Test: `broker/internal/registry/{manifest_test,tokens_test}.go`

**Interfaces:**
- Produces:
  - `registry.Tool` interface: `Name() string`, `InputSchema() json.RawMessage`, `OutputSchema() json.RawMessage`, `Scopes() []string`, `Reversibility() Reversibility`, `CachePolicy() CachePolicy`, `TokenCap() int`, `Call(ctx, Principal, json.RawMessage) (Result, error)`
  - `registry.Reversibility` ∈ {`Reversible`, `Recoverable`, `Irreversible`}
  - `registry.New(...Tool) (*Registry, error)`; `(*Registry).ManifestBytes() []byte`; `(*Registry).ManifestHash() string`; `(*Registry).TokenCount() int`

- [ ] **Step 1:** Write `TestToolsListByteStable` — 100 calls, hash each body, assert exactly one distinct SHA-256.
- [ ] **Step 2:** Write `TestStableAcrossReload`, `TestCacheableFieldsPresent` (all five list/read endpoints carry `ttlMs` and `cacheScope`), and `TestSortIsBytewise` using the case pair `Warehouse` vs `warehouse`.
- [ ] **Step 3:** Run; expect FAIL.
- [ ] **Step 4:** Implement the canonical ordering of §8.3: byte-wise name sort, fixed struct field order, sorted `required` and `enum` arrays, no insignificant whitespace, `sha256:`-prefixed hex hash.
- [ ] **Step 5:** Serve **precomputed bytes** from `tools/list`; do not re-serialize per request.
- [ ] **Step 6:** Implement `tokens.go` with a named tokenizer and a stated method; wire `make measure`.
- [ ] **Step 7:** Run all; run `make measure`.
- [ ] **Step 8:** Commit, PR, merge.

**Acceptance:**
```bash
go test ./broker/internal/registry/... -v
make measure
```

**Pitfall:** `cacheScope: public` for a tool list that varies by scope is a cross-tenant disclosure through a shared intermediary. `private` here, with the reason in a comment.

---

### Task 4 — WP-4: Tool discipline and `warehouse.query`

**Branch:** `feat/wp-4-tool-discipline` · `SN-CAP-12`, `SN-CAP-14` · `SN-FR-15`–`SN-FR-17`, `SN-FR-20`

**Files:**
- Create: `broker/internal/tools/warehouse/{describe,query,sqlguard,format}.go`, `broker/internal/store/migrations/0002_warehouse_seed.{up,down}.sql`
- Test: `broker/internal/tools/warehouse/{query_test,sqlguard_test,format_test}.go`

**Interfaces:**
- Consumes: `registry.Tool`, `handles.Minter`.
- Produces: `warehouse.NewQueryTool(store, minter, cfg) registry.Tool`; standard argument `response_format ∈ {concise, detailed}`.

- [ ] **Step 1:** Write `TestConciseIsSmallerThanDetailed` recording both token counts per tool.
- [ ] **Step 2:** Write `TestOutOfScopeTableRejected`, `TestStatementTimeoutCancelsServerSide`, `TestOverCapReturnsHandlePlusSummary`, `TestActionableErrorNamesFieldAndExample`.
- [ ] **Step 3:** Run; expect FAIL.
- [ ] **Step 4:** Implement `sqlguard.go` — **allowlist schemas and tables, parse the statement, cap rows and time**. Never string-inspect arbitrary SQL for safety.
- [ ] **Step 5:** Implement `query.go`, `describe.go`, `format.go` (token cap default 25,000; over-cap returns a `query_result` handle plus a summary).
- [ ] **Step 6:** Run all.
- [ ] **Step 7:** Commit, PR, merge.

**Acceptance:**
```bash
go test ./broker/internal/tools/... -v
```

---

### Task 5 — WP-5: State handles

**Branch:** `feat/wp-5-state-handles` · `SN-CAP-07` · `SN-FR-08`

**Files:**
- Create: `broker/internal/handles/{mint,resolve,gc}.go`, `broker/internal/store/migrations/0003_state_handles.{up,down}.sql`
- Test: `broker/internal/handles/{mint_test,resolve_test,gc_test}.go`

**Interfaces:**
- Produces:
  - `handles.Mint(ctx, p Principal, kind string, payload json.RawMessage, ttl time.Duration) (Handle, error)`
  - `handles.Resolve(ctx, p Principal, id string) (json.RawMessage, error)` — **sole** resolution path
  - `handles.ErrNotResolvable` — the single error returned for both "does not exist" and "not yours"

- [ ] **Step 1:** Write `TestHandleIsCSPRNG` (≥128 bits entropy, no sequential structure across 1000 mints).
- [ ] **Step 2:** Write the two named negative tests: `TestCrossPrincipalHandleRefused` and `TestNonexistentAndUnauthorizedAreIndistinguishable` (identical code **and** identical message).
- [ ] **Step 3:** Write `TestExpiredHandleRefused`, `TestRevokedHandleRefused`, `TestGCRemovesExpired`.
- [ ] **Step 4:** Run; expect FAIL.
- [ ] **Step 5:** Implement the single-query resolution of §7.4 exactly — `handle_id`, `tenant_id`, `principal_id`, `revoked_at IS NULL`, `expires_at > now()`.
- [ ] **Step 6:** Run all.
- [ ] **Step 7:** Commit, PR, merge.

**Pitfall:** Caching a resolved handle in memory and skipping the re-check on second use. Every resolution re-verifies.

---

### Task 6 — WP-6: MRTR engine and idempotent replay

**Branch:** `feat/wp-6-mrtr-idempotency` · `SN-CAP-09`, `SN-CAP-10` · `SN-FR-10`–`SN-FR-12`

**The hardest task. Do not compress it.**

**Files:**
- Create: `broker/internal/mrtr/{state,engine,idempotency}.go`, `broker/internal/tools/ops/{plan,apply}.go`, `broker/internal/store/migrations/0004_mrtr_flows.{up,down}.sql`
- Test: `broker/internal/mrtr/{state_test,engine_test,idempotency_test}.go`, `tests/e2e/test_mrtr.py`

**Interfaces:**
- Produces:
  - `mrtr.Seal(key [32]byte, correlationID string, expiry time.Time, toolName string) (string, error)`
  - `mrtr.Unseal(key [32]byte, requestState string, toolName string) (correlationID string, expiry time.Time, err error)` — tool name bound as AAD
  - `mrtr.Engine.Begin(ctx, p, toolName string, args json.RawMessage, reqs []InputRequest) (Flow, string, error)`
  - `mrtr.Engine.Resume(ctx, p, requestState string, args json.RawMessage, responses json.RawMessage) (Outcome, error)`

- [ ] **Step 1:** Draw the §8.5 state machine as a comment at the top of `engine.go` before writing code.
- [ ] **Step 2:** Write all seven §8.5 tests by name — `TestCorrelationIgnoresRequestID`, `TestTamperedRequestStateRejected`, `TestMutatedArgumentsRejected`, `TestCrossPrincipalRetryRejected`, `TestDuplicateRetryIsIdempotent`, `TestExpiredFlowRejected`, `TestReplayWindowExpiry`.
- [ ] **Step 3:** `TestDuplicateRetryIsIdempotent` asserts on a **side-effect counter** (`SELECT count(*) FROM deployments`), never on the response body.
- [ ] **Step 4:** Run; expect FAIL.
- [ ] **Step 5:** Implement `state.go` — AEAD seal with the tool name as additional authenticated data.
- [ ] **Step 6:** Implement `idempotency.go` — `arguments_hash`, recorded-result replay, `replay_window` distinct from `flow_ttl`.
- [ ] **Step 7:** Implement `engine.go`. **The effect and the record commit in one transaction.**
- [ ] **Step 8:** Implement `ops.deployment_apply` as `Irreversible` so MRTR is required by the type system, not by memory.
- [ ] **Step 9:** Run unit and e2e.
- [ ] **Step 10:** Commit, PR, merge.

**Definition of done:** `ops.deployment_apply` → `input_required` → approve → retry completes → replay the identical retry → identical response, **one** deployment.

---

### Task 7 — WP-7: Audience validation

**Branch:** `feat/wp-7-audience-validation` · `SN-CAP-21` · `SN-FR-28`

**Files:**
- Create: `broker/internal/authz/{audience,scopes,outbound}.go`
- Test: `broker/internal/authz/{audience_test,outbound_test}.go`

**Interfaces:**
- Produces: `authz.Validate(tok string, cfg Config) (Principal, error)`; sentinel errors `ErrUnauthenticated`, `ErrWrongAudience`, `ErrWrongIssuer`, `ErrExpired`.

- [ ] **Step 1:** Write `TestTokenForAnotherAudienceRejected` — structurally valid, correctly signed, `aud` names a different service.
- [ ] **Step 2:** Write `TestAudienceMatchIsExactNotPrefix` (`https://broker.example` must not accept `https://broker.example.evil`).
- [ ] **Step 3:** Write `TestInboundTokenNeverForwarded` — capture every outbound request made while serving a call; assert the inbound token string appears in none.
- [ ] **Step 4:** Run; expect FAIL.
- [ ] **Step 5:** Implement `audience.go` exactly as §8.6, and `outbound.go` sourcing the broker's own credential.
- [ ] **Step 6:** Run all.
- [ ] **Step 7:** Commit, PR, merge.

---

### Task 8 — WP-8: Audit log and hash chain

**Branch:** `feat/wp-8-audit-chain` · `SN-CAP-25` · `SN-FR-32`, `SN-FR-33`

**Files:**
- Create: `broker/internal/audit/{writer,chain,canonical}.go`, `broker/internal/store/migrations/0005_audit.{up,down}.sql`, `broker/cmd/broker/audit_verify.go`
- Test: `broker/internal/audit/{chain_test,writer_test,canonical_test}.go`

**Interfaces:**
- Produces:
  - `audit.CanonicalJSON(v any) ([]byte, error)` — sorted keys, no insignificant whitespace, **no floats**
  - `audit.RowHash(prev string, fields Auditable) string`
  - `audit.Verify(ctx, tenant uuid.UUID, from, to time.Time) (*Break, error)`

- [ ] **Step 1:** Write `TestCanonicalJSONRejectsFloats` and `TestCanonicalJSONSortsKeys`.
- [ ] **Step 2:** Write `TestChainDetectsTampering` — mutate a row via a superuser connection, assert verification points at exactly that row.
- [ ] **Step 3:** Write `TestAppRoleCannotUpdateOrDelete` — attempt both as `broker_app`, assert permission denied.
- [ ] **Step 4:** Write `TestAuditFailureFailsInvocation` and `TestPartitionAutoCreated` (advance the clock across a month boundary; assert the insert succeeds).
- [ ] **Step 5:** Run; expect FAIL.
- [ ] **Step 6:** Write the migration with the `REVOKE UPDATE, DELETE, TRUNCATE` / `GRANT INSERT, SELECT` pair and **partition automation** for the current and next month plus a rollover.
- [ ] **Step 7:** Implement `canonical.go`, `chain.go`, `writer.go` (fail-closed, in-transaction with the effect), and `broker audit verify`.
- [ ] **Step 8:** Run all.
- [ ] **Step 9:** Commit, PR, merge.

**Acceptance:**
```bash
go test ./broker/internal/audit/... -v
broker audit verify --from 2026-09-01 --to 2026-09-30
```

---

### Task 9 — WP-9: Harness probe, rule catalog, fixtures

**Branch:** `feat/wp-9-harness-catalog` · `SN-CAP-27` · `SN-FR-35`, `SN-FR-40`

**Files:**
- Create: `harness/src/sentinel/probe/{transport,client}.py`, `catalog/base.py`, `catalog/must/*.py`, `catalog/should/*.py`, `fixtures/server/{common,nonconformant,conformant}.py`
- Test: `tests/harness/test_catalog_validate.py`, `tests/harness/test_fixture_oracle.py`

**Interfaces:**
- Produces:
  - `Rule` protocol with `id`, `severity`, `citation`, `verifiability`, `remediation`, `fixtures`, `async evaluate(probe) -> RuleResult`
  - `Outcome ∈ {PASS, FAIL, NOT_APPLICABLE, INDETERMINATE}`
  - Rule ID format `MCP/2026-07-28/MUST/<slug>`

- [ ] **Step 1:** Write `test_every_rule_has_citation_and_remediation` over the whole registry.
- [ ] **Step 2:** Write `test_nonconformant_fixture_trips_at_least_twenty_musts` and `test_conformant_fixture_trips_zero`.
- [ ] **Step 3:** Write `test_harness_never_imports_broker` — walk the harness source, assert no import references `broker`.
- [ ] **Step 4:** Run; expect FAIL.
- [ ] **Step 5:** Implement the probe **by hand from the spec** — no MCP SDK — with deliberate-malformation hooks and per-rule timeouts.
- [ ] **Step 6:** Implement 25 MUST rules, each citing a spec anchor. Rules that cannot be proven black-box are `UNVERIFIABLE` and return `INDETERMINATE`.
- [ ] **Step 7:** Implement both fixtures; tag each seeded violation with its rule ID in a comment.
- [ ] **Step 8:** Run all; run the scan acceptance.
- [ ] **Step 9:** Commit, PR, merge.

**Acceptance:**
```bash
uv run sentinel catalog validate
uv run sentinel fixture serve --profile nonconformant &
uv run sentinel scan --endpoint http://localhost:9000/mcp --format text
```

**Pitfall:** Scoring an unverifiable MUST as a pass is the fastest way to lose a reviewer's trust.

---

### Task 10 — WP-10: Grading, JSON, SARIF, CI gate

**Branch:** `feat/wp-10-grading-sarif` · `SN-CAP-28` · `SN-FR-37`

**Files:**
- Create: `harness/src/sentinel/grade.py`, `report/{json_report,sarif,text}.py`, `.github/workflows/conformance.yml`
- Test: `tests/harness/test_exit_codes.py`, `tests/harness/test_sarif_shape.py`

**Interfaces:**
- Produces: `grade.evaluate(results, gate) -> GradeReport` with `.exit_code` ∈ {0,1}; `sarif.render(report) -> dict` conforming to SARIF 2.1.0.

- [ ] **Step 1:** Write `test_indeterminate_does_not_fail_gate`, `test_must_fail_exits_one`, `test_clean_scan_exits_zero`, `test_harness_error_is_not_exit_one`.
- [ ] **Step 2:** Write `test_sarif_validates_against_schema`.
- [ ] **Step 3:** Run; expect FAIL.
- [ ] **Step 4:** Implement `grade.py` and the three renderers.
- [ ] **Step 5:** Write `conformance.yml` scanning Broker **and** asserting the non-conformant fixture fails the gate.
- [ ] **Step 6:** Run all three acceptance commands and check `$?` each time.
- [ ] **Step 7:** Commit, PR, merge.

---

### Task 11 — WP-11: Deprecation inventory

**Branch:** `feat/wp-11-deprecations` · `SN-CAP-29` · `SN-FR-38`

**Files:**
- Create: `harness/src/sentinel/catalog/deprecations.py`
- Test: `tests/harness/test_deprecations.py`

- [ ] **Step 1:** Write `test_all_five_detected_against_fixture` and `test_none_detected_against_broker`.
- [ ] **Step 2:** Write `test_removal_date_is_twelve_months_and_phrased_on_or_after`.
- [ ] **Step 3:** Run; expect FAIL.
- [ ] **Step 4:** Implement detection for **Roots, Sampling, Logging** (SEP-2577), **HTTP+SSE transport**, **OAuth Dynamic Client Registration**, and `includeContext ∈ {thisServer, allServers}`.
- [ ] **Step 5:** Compute removal as deprecation date + 12 months, phrased **"on or after"**.
- [ ] **Step 6:** Run all.
- [ ] **Step 7:** Commit, PR, merge.

---

### Task 12 — WP-12: Measurements, migration guide, README, demo

**Branch:** `feat/wp-12-measurements-docs`

**Files:**
- Create: `MEASUREMENTS.md`, `docs/MIGRATION.md`, `docs/runbook.md`, `docs/demo/README.md`
- Modify: `README.md`, `Makefile` (`measure` target)

- [ ] **Step 1:** Implement `make measure` writing all six measurements: manifest token count before/after consolidation; per-tool `concise` vs `detailed`; `tools/list` distinct-SHA-256 count across 100 calls; MUST recall against the non-conformant fixture; false positives against the conformant one (must be 0); scan wall-clock p50/p95.
- [ ] **Step 2:** Run `make measure`; commit the generated `MEASUREMENTS.md`.
- [ ] **Step 3:** Write `docs/MIGRATION.md` — the `2026-07-28` changelog table, each row annotated with the concrete work required and how Sentinel Conformance detects it.
- [ ] **Step 4:** Write `README.md` including the **limitations section listing which MUSTs are unverifiable black-box**.
- [ ] **Step 5:** Write `docs/runbook.md` and the nine-step demo script.
- [ ] **Step 6:** Run the full `make check` and both scans.
- [ ] **Step 7:** Commit, PR, merge.

---

## Definition of done

The §15 checklist of the spec, verbatim, every box ticked and each backed by a command whose output is pasted into the PR that claims it.
