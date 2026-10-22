# The Go server kit

`mcp/` is the reusable half of the broker: the packages that make a server native to MCP
`2026-07-28`, extracted from `broker/internal/` so you can import them.

```go
import "github.com/patsypppe/sentinel/mcp/server"
```

## The smallest server

[`mcp/example`](../mcp/example/example.go) is one tool, no database, no configuration:

```go
srv, err := server.New(server.Options{
    Info:          envelope.Info{Name: "my-server", Version: "0.1.0"},
    Tools:         []registry.Tool{MyTool{}},
    Authenticator: server.InsecureAnonymous(registry.Principal{ID: "dev", Scopes: []string{"my:scope"}}),
})
if err != nil { log.Fatal(err) }
srv.ListenAndServe(ctx, ":8080")
```

`make check` **builds, serves and scans the example** with the conformance harness and requires
`--gate must` and `--gate security` to pass, so the kit cannot drift away from the specification
without a build going red. Run it yourself:

```bash
go run ./mcp/example/cmd -addr :8080 &
sentinel scan --endpoint http://localhost:8080/mcp --gate must
```

## What `server.New` decides for you

- **No default authenticator.** A server that has not said how it identifies callers is refused at
  construction, because an authentication layer that was never configured must fail closed.
  `server.InsecureAnonymous` is the development escape hatch and its name is the warning.
- **A default audit sink, in memory.** The rule is that every invocation is audited and a failed
  write fails the call, so "no sink" would make the rule opt-in. `audit.MemorySink` is for
  development and tests: it is not durable and not tamper-evident. For real traffic use the
  hash-chained, grant-protected `audit.PoolSink`, or your own `transport.AuditSink`.
- **Every result carries `resultType` and `serverInfo`**, `tools/list` is built once and served as
  precomputed bytes (one SHA-256 across any number of calls), and every list result carries
  `ttlMs` and `cacheScope`.
- **The header contract**: `Mcp-Method` on every POST, `Mcp-Name` on `tools/call`,
  `resources/read` and `prompts/get` only, `MCP-Protocol-Version` matching the body, `Origin`
  validated; a missing or disagreeing header is `-32020` with HTTP 400.
- **Removed methods** (`initialize`, `ping`, `resources/subscribe`, ...) answer method-not-found
  with HTTP 404 and name the revision that removed them.

## A tool

`registry.Tool` has nine methods and **no embeddable default**, because a default is how a tool
skips a decision. Every one has to be answered:

| | |
|---|---|
| `Name`, `Description`, `InputSchema`, `OutputSchema` | what a model reads |
| `Scopes` | all of them are required of the principal; exact match, never a prefix |
| `Reversibility` | `Reversible`, `Recoverable` or `Irreversible`; drives whether MRTR confirmation is required |
| `CachePolicy`, `TokenCap` | an over-cap result returns a handle plus a summary, never a silent truncation |

## Packages

| Package | |
|---|---|
| `mcp/server` | `New`, `DefaultMux`, `InsecureAnonymous` |
| `mcp/envelope` | JSON-RPC envelope, the error taxonomy (`errors.go` is the only place a code is defined), `_meta`, negotiation |
| `mcp/registry` | the `Tool` interface, the deterministic manifest, token accounting |
| `mcp/transport` | Streamable HTTP and stdio over one dispatch pipeline; `Settings`, the `Authenticator` and `AuditSink` seams |
| `mcp/authz` | audience validation (the only place a token is accepted), scopes, the outbound credential |
| `mcp/handles` | server-minted, principal-bound handles; `resolve.go` is the only place one becomes usable |
| `mcp/mrtr` | sealed `requestState`, idempotent resume |
| `mcp/audit` | hash chain, redaction, verification; `MemorySink` and the Postgres `PoolSink` |
| `mcp/canonical` | byte-stable JSON |
| `mcp/store` | the pgx pool and the migrations |

## Tracing

`otlp.New(endpoint, service, logger)` returns an exporter that sends one span per dispatched request to an OTLP/HTTP-JSON
collector (port 4318; 4317 is gRPC and is refused). Wire it with
`server.Options{SpanRecorder: exp.Record}`, call `exp.Start(ctx)`, and `defer exp.Wait()`. Spans
carry method, tool name, outcome and trace context, never arguments or principal. The broker
enables it when `BROKER_OTEL_ENDPOINT` is set.

## Honest limits

- **`handles`, `mrtr`, `audit` (`PoolSink`) and `store` still carry their Postgres implementations
  in the same packages.** The `AuditSink` seam is an interface, so the minimal path needs no
  database, but a server that uses handles or MRTR needs Postgres today. This is deliberate and
  not yet changed: `handles.Resolve` enforces tenant, principal and expiry inside one SQL
  statement, so the database is what refuses a stolen handle, and MRTR's exactly-once guarantee
  rests on a single transaction. Moving either behind an interface forces a choice between the
  backend returning a row that the kit re-checks, or a backend contract that must itself enforce
  those invariants. That is a security-design decision for the owner, not a refactor.
- `transport` takes a two-field `Settings{AllowedOrigins, AllowLegacyUnversioned}`, not the
  broker's configuration struct; the broker maps its own configuration onto it.
- The broker (`broker/`) is the reference application built on this kit. It proves the kit
  implements the specification; the example is what you copy.
