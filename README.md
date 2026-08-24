# Sentinel

**A stateless MCP server, and the conformance harness that grades it.**

[![ci](https://github.com/patsypppe/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/patsypppe/sentinel/actions/workflows/ci.yml)
[![conformance](https://github.com/patsypppe/sentinel/actions/workflows/conformance.yml/badge.svg)](https://github.com/patsypppe/sentinel/actions/workflows/conformance.yml)

On **28 July 2026** the Model Context Protocol shipped the largest breaking revision in its
history: it converted MCP from a stateful, session-based, bidirectional protocol into a
**stateless request/response protocol**. Sessions are gone. The `initialize` handshake is gone.
`server/discover` is mandatory. Server-initiated requests were replaced wholesale by Multi
Round-Trip Requests. `CacheableResult` became required. Sampling, Roots, Logging, HTTP+SSE
transport and OAuth Dynamic Client Registration were all deprecated on a twelve-month clock.

Every MCP server in the wild was written against the old idioms.

| | |
|---|---|
| **`broker/`** | A Go MCP server built **natively** on `2026-07-28` — stateless, handle-based, MRTR-only, audited. |
| **`harness/`** | **`sentinel`**, a conformance harness that scans *any* MCP server, grades it against the normative requirements with a spec citation per rule, and inventories its deprecated-feature debt. |

They are coupled deliberately: the harness's credibility comes from grading a server that is not
its own, and the server's credibility comes from being graded. The harness never imports server
internals and runs against any endpoint URL.

---

## The two scans

```console
$ sentinel scan --endpoint http://localhost:9000/mcp --gate must     # an unmigrated server
MUST: 2 pass, 25 fail, 5 indeterminate, 0 n/a
SHOULD: 1 pass, 3 fail, 0 n/a
exit 1

$ sentinel scan --endpoint http://localhost:8080/mcp --gate must --token "$TOKEN"   # broker
MUST: 27 pass, 0 fail, 5 indeterminate, 0 n/a
SHOULD: 4 pass, 0 fail, 0 n/a
exit 0
```

The broker's resource and tool methods are authenticated, so its scan carries a token — minted with
`broker mint-token`, as [`docs/runbook.md`](docs/runbook.md) shows and as CI does. The fixture needs
none, which is part of what makes it unmigrated.

A failure names the rule, what was observed, what to change, and the clause it comes from:

```
FAIL  MCP/2026-07-28/MUST/header-body-mismatch-rejected
      A header disagreeing with the body is rejected with -32020
      observed:    a request whose Mcp-Method header said tools/list while its body
                   called tools/call was SERVED; a gateway routing on the header
                   authorized a different request than the one that ran
      remediation: Compare Mcp-Method and Mcp-Name against the JSON-RPC body and return
                   -32020 HeaderMismatch when they disagree. This is what makes the
                   headers BINDING…
      spec:        https://modelcontextprotocol.io/specification/2026-07-28/…
```

And the deprecation debt, with removal windows:

```console
$ sentinel deprecations --endpoint http://localhost:9000/mcp
6 deprecated feature(s) in use

  IN USE  Roots  (SEP-2577)
          deprecated:  2026-07-28
          removable on or after 2027-07-28 (10 month(s) from now)
          replace with: explicit tool arguments naming the paths a tool may touch
```

---

## Limitations, stated plainly

**Five MUST requirements cannot be verified black-box.** `sentinel` reports them as
`INDETERMINATE` — never as passes — excludes them from the gate, and prints them on every scan:

| Rule | Why a scan cannot settle it | What would |
|---|---|---|
| `token-audience-validated` | The harness cannot mint a token signed by your issuer, and a forged one is rejected for its signature — which proves nothing about the audience check. | Mint one with your issuer and a different audience; confirm the refusal. |
| `no-token-passthrough` | What a server sends to its own dependencies is invisible from the client side. | Capture the server's egress during an authenticated call. |
| `handle-possession-is-not-authentication` | Needs **two** authenticated principals; a scan has one. | Mint a handle as one, present it as the other. |
| `mrtr-retries-are-idempotent` | A duplicate retry that returns the right answer is indistinguishable from one that performed the effect twice *and* returned the right answer. | Count the effect at its source, not in the reply. |
| `invocations-are-audited` | An audit log is not exposed over MCP; a server claiming to keep one would be believed on its own word. | Read the log and verify its chain. |

**A clean scan is not a clean bill of health.** A harness that scored these as passes would be
lying, and a tool that implied otherwise would be worse than no tool.

The broker implements all five, and proves it with tests that *do* have the access a scan lacks —
`TestTokenForAnotherAudienceRejected`, `TestInboundTokenNeverForwarded`,
`TestCrossPrincipalHandleRefused`, `TestDuplicateRetryIsIdempotent`, `TestChainDetectsTampering`.
That is the point of shipping both: the scan says what it can see, and the server's own suite
covers what it cannot.

### Rule lifecycle

**A rule ID never changes meaning.** A report from six months ago names rules by ID and nothing
else, so redefining one silently rewrites what that report said. When a rule turns out to be wrong,
it is deprecated and a successor is published under a new ID.

Three rules were corrected in **0.2.0**, all in the same direction — `sentinel` was demanding more
than the specification does, which is the false positive `MEASUREMENTS.md` publishes as zero:

| Deprecated | Successor | Why |
|---|---|---|
| `MUST/server-info-echoed` | `SHOULD/server-info-echoed` | The spec marks `serverInfo` *Required: No*. Omitting it costs you cache keys and attribution; it does not make you non-conformant. |
| `MUST/tools-list-is-deterministic` | `SHOULD/tools-list-is-deterministic` | "Servers **SHOULD** return tools in a deterministic order." The MUST in the same paragraph is a different property — the set MUST NOT vary per-connection — now checked by `MUST/tools-list-connection-independent`, which opens a second connection because twenty calls on one could never have seen it. |
| `SHOULD/tools-sorted-by-name` | `SENTINEL/STYLE/tools-sorted-by-name` | The specification asks for a deterministic order and never for a sorted one, so a stable unsorted manifest conforms fully. It is still a good idea, so it moved to the beyond-spec namespace rather than being deleted. A `SENTINEL/` rule carries a rationale instead of a citation and can never fail a spec gate. |

Deprecated rules are excluded from a scan by default and never deleted. Pass
`--include-deprecated-rules` to evaluate them as well, which is how you reproduce a report written
before the correction and see what changed.

---

## Measurements

Regenerated by `make measure`; see [`MEASUREMENTS.md`](MEASUREMENTS.md) for the method behind each.

| Measurement | Result |
|---|---|
| Recall against the non-conformant fixture | **100%** (29 of 29 seeded violations detected) |
| False positives against the conformant fixture | **0** |
| `tools/list` determinism | **1** distinct SHA-256 across 100 calls and 5 cold rebuilds |
| Manifest token count | 2,032 tokens across 4 tools |
| `concise` vs `detailed` responses | up to **49.3%** fewer tokens |
| Scan wall-clock | p50 ~50 ms, p95 ~125 ms |

Recall's denominator comes from the fixture's own `SEEDED_VIOLATIONS` list, not from anything in
the harness — a scanner supplying its own denominator would be grading its own homework — and a
test asserts that list matches the violations tagged in the fixture's source, so it cannot quietly
shrink.

---

## Quick start

```bash
make up                      # postgres + broker + envoy + smokescreen + otel-collector
make check                   # golangci-lint, go test -race, ruff, mypy, pytest
make scan-broker             # grade the broker against its own harness
make scan-fixture            # grade an unmigrated server; expected to exit 1
make demo                    # the nine-step demo
```

Requires Go 1.23+, Python 3.12, uv ≥ 0.5 and Docker. **No model API key is required anywhere** —
the broker serves tools, it does not call models, which is why CI is fast, free, and never flaky
for a reason outside this repository.

### Scanning your own server

```bash
uv run sentinel scan --endpoint https://your-server.example/mcp --gate must \
  --token "$TOKEN" --format sarif --out scan.sarif
uv run sentinel deprecations --endpoint https://your-server.example/mcp
```

Exit codes are a contract: **0** passed, **1** the *target* failed the gate, **2** the *scanner*
could not run. CI needs to tell "the server is wrong" from "the scanner broke", so those are never
conflated.

The SARIF renders natively in GitHub code scanning. Because a conformance finding is about a
service rather than a file, pass `--sarif-anchor <path>` to choose the repo file annotations attach
to; a scan of a third-party server has no such file and should use `--format json`.

---

## What the broker demonstrates

- **Stateless.** No session, nothing keyed by connection. Cross-call state is a server-minted
  handle bound to its principal, re-verified on **every** resolution — `handles/resolve.go` is the
  only place a handle becomes usable, and it returns one indistinguishable error for "does not
  exist", "not yours", "expired" and "revoked".
- **MRTR with exactly-once effects.** `requestState` is AEAD-sealed with the tool name as
  additional authenticated data; the effect and its recorded result commit in one transaction; a
  duplicate retry replays the recorded result **verbatim** and performs zero further effects.
- **Deterministic manifest.** Built once, sorted byte-wise, served as precomputed bytes.
- **The header contract, demonstrated rather than asserted.** Envoy routes and authorizes on
  `Mcp-Method` / `Mcp-Name` with **no body-parsing filter anywhere** — a test parses the config and
  checks — and the broker rejects a body that disagrees with the headers. Routed by header,
  rejected by body check.
- **Audience validation.** Exact-membership `aud` check; the inbound token is never carried onto
  the principal, so there is nothing to forward downstream even by accident.
- **An append-only, hash-chained audit log.** Immutability is enforced by database grants rather
  than convention, and `broker audit verify` walks the chain and names the first break.

---

## Documentation

- **[`docs/MIGRATION.md`](docs/MIGRATION.md)** — what changed in `2026-07-28` and what it costs
  you, with the mistakes worth avoiding and a migration order that works.
- [`docs/HANDOFF.md`](docs/HANDOFF.md) — the implementation specification (SN-HND-001).
- [`docs/runbook.md`](docs/runbook.md) — running, operating and debugging the stack.
- [`docs/demo/README.md`](docs/demo/README.md) — the nine-step demo.
- [`CLAUDE.md`](CLAUDE.md) — the four rules and the single-source-file constraints.

## Precedence

Where this repository and the
[MCP specification](https://modelcontextprotocol.io/specification/2026-07-28/) disagree,
**the specification wins and this repository is wrong.**

## Scope

This is the MVP tier of `SN-PRD-001`. Deliberately **not** here: OAuth beyond audience validation
(CIMD, consent registry, scope step-up), `subscriptions/listen`, the tasks extension, MCP Apps, and
rate limiting or tenant-isolation *enforcement* — the `tenant_id` columns exist throughout, the
policy does not. See `docs/HANDOFF.md` §3.2 for why each is out and when it returns.

## License

MIT — see [`LICENSE`](LICENSE).
