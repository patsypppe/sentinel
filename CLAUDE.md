# Sentinel — working instructions

Two products in one repository:

- **`broker/`** — a Go MCP server built natively on the **stateless** MCP `2026-07-28` specification.
- **`harness/`** — `sentinel`, a Python conformance harness that grades *any* MCP server.

The spec is `docs/HANDOFF.md` (SN-HND-001). **Where this repository and the
[MCP specification](https://modelcontextprotocol.io/specification/2026-07-28/) disagree, the spec wins.**

## The four rules

1. **Stateless. Handles are data, never credentials.** No session, nothing keyed by connection.
   Cross-call state is a server-minted handle passed as an ordinary tool argument. Possession of a
   handle is not authentication — every resolution re-verifies principal and tenant.
2. **No server-initiated requests. MRTR only, and it must be idempotent.** `resultType:
   "input_required"` + `inputRequests`; the *client* retries with `inputResponses`. Correlation is
   the sealed `requestState`, never the JSON-RPC id. A duplicate retry returns the recorded result
   and performs **zero** additional side effects.
3. **Deterministic where the spec asks for determinism.** 100 `tools/list` calls → one SHA-256.
   Every list/read result carries `ttlMs` and `cacheScope`. `Mcp-Method` required on every POST; `Mcp-Name` on
   `tools/call`, `resources/read`, `prompts/get` only.
4. **Every invocation is audited; no token is trusted that was not issued for this server.**
   Validate the audience exactly. Never forward an inbound token downstream. If the audit write
   fails, the invocation fails.

## Never cut

`resultType` + `serverInfo` on every result · handle binding · MRTR idempotency · the audit row ·
the non-conformant fixture server.

## Single-source files (audit the security posture by reading three files)

| File | Sole authority for |
|---|---|
| `broker/internal/envelope/errors.go` | every error code |
| `broker/internal/handles/resolve.go` | making a handle usable |
| `broker/internal/authz/audience.go` | accepting a token |

## Hard constraints

- **Structs, never `map[string]any`** for anything serialized deterministically. `json.RawMessage`
  for pass-through — a number through `any` becomes `float64` and breaks hashes.
- Error codes `-32020`…`-32099` are **reserved for the spec**, and `-32000`…`-32019` is the
  sub-range it **retired** — new implementations SHOULD NOT use it at all. Ours live at
  `1000`…`1019`, outside the JSON-RPC reserved range entirely.
- The harness **must never import broker internals** and must run against any endpoint URL.
- The probe is a **deliberately literal** MCP client. **No MCP SDK** — an SDK that helpfully adds
  `Mcp-Method` makes the rule requiring `Mcp-Method` untestable.
- An unverifiable MUST returns `INDETERMINATE`, never a false pass.
- No model API key is required anywhere. Broker serves tools; it does not call models.
- Do not add: a web framework, an ORM, or a JSON-RPC library that hides the envelope.

## Commands

```bash
make check      # golangci-lint + go test ./... + ruff + mypy + pytest -m unit
make up         # docker compose up -d
make test-e2e   # compose-backed end-to-end suite
make measure    # regenerate MEASUREMENTS.md
make demo       # the nine-step demo from docs/HANDOFF.md §13
```

Go lives behind Homebrew on this machine: `export PATH="/opt/homebrew/bin:$PATH"` (Go 1.23+ required).

## Commit format

`<type>: <description>` — `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`.
One branch and one PR per work package (`feat/wp-N-<slug>`).
