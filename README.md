# Sentinel

**A stateless MCP server, and the conformance harness that grades it.**

On **28 July 2026** the Model Context Protocol shipped the largest breaking revision in its
history: it converted MCP from a stateful, session-based, bidirectional protocol into a
**stateless request/response protocol**. Sessions are gone. The `initialize` handshake is gone.
`server/discover` is mandatory. Server-initiated requests were replaced wholesale by Multi
Round-Trip Requests. `CacheableResult` became required. Sampling, Roots, Logging, HTTP+SSE
transport and OAuth Dynamic Client Registration were all deprecated on a twelve-month clock.

Every MCP server in the wild was written against the old idioms. This repository is two things
sold together:

| | |
|---|---|
| **`broker/`** | A Go MCP server built **natively** on `2026-07-28` — stateless, handle-based, MRTR-only, audited. |
| **`harness/`** | **`sentinel`**, a conformance harness that scans *any* MCP server, grades it against the normative requirements with a spec citation per rule, and inventories its deprecated-feature debt. |

They are coupled deliberately. The harness's credibility comes from grading a server that is not
its own; the server's credibility comes from being graded. The harness never imports server
internals and runs against any endpoint URL.

## Status

**Work in progress.** See `docs/superpowers/plans/2026-08-22-sentinel-mvp.md` for the work-package
plan and `docs/HANDOFF.md` for the specification this implements.

| WP | Capability | State |
|---|---|---|
| WP-0 | Repository bootstrap | ✅ |
| WP-1 | Envelope, discovery, negotiation, error taxonomy | ⏳ |
| WP-2 | Header contract and Envoy routing | ⏳ |
| WP-3 | Registry, deterministic `tools/list`, `CacheableResult` | ⏳ |
| WP-4 | Tool discipline and `warehouse.query` | ⏳ |
| WP-5 | Server-minted state handles | ⏳ |
| WP-6 | MRTR engine and idempotent replay | ⏳ |
| WP-7 | Audience validation | ⏳ |
| WP-8 | Audit log and hash chain | ⏳ |
| WP-9 | Harness probe, rule catalog, fixtures | ⏳ |
| WP-10 | Grading, JSON, SARIF, CI gate | ⏳ |
| WP-11 | Deprecation inventory | ⏳ |
| WP-12 | Measurements, migration guide, demo | ⏳ |

## Quick start

```bash
make up          # postgres + broker + envoy + smokescreen + otel-collector
make check       # golangci-lint, go test, ruff, mypy, pytest
make scan-broker # grade the broker against its own harness
```

Requires Go 1.23+, Python 3.12, uv ≥ 0.5, and Docker. **No model API key is required anywhere** —
the broker serves tools, it does not call models, which is why CI is fast, free, and never flaky
for a reason outside this repository.

## Documentation

- **`docs/HANDOFF.md`** — the implementation specification (SN-HND-001).
- **`docs/MIGRATION.md`** — what changed in MCP `2026-07-28` and what it costs you. *(WP-12)*
- **`CLAUDE.md`** — the four rules and the single-source-file constraints.

## Precedence

Where this repository and the
[MCP specification](https://modelcontextprotocol.io/specification/2026-07-28/) disagree,
**the specification wins and this repository is wrong.**

## License

MIT — see `LICENSE`.
