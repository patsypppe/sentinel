# Sentinel vs the official MCP conformance suite

Measured 2026-10-21. Reproduce with `benchmarks/official-suite/run.sh`; the raw
results are in `benchmarks/official-suite/results/`.

| | |
|---|---|
| Official suite | `@modelcontextprotocol/conformance@0.2.0-alpha.12`, `--requirements 2026-07-28` |
| Official reference server | `everythingServer.ts` from `modelcontextprotocol/typescript-sdk` at `c05225a` (2026-10-21) — the server the suite's expected-failures baseline is written for |
| Sentinel | 0.4.0 (this branch); 0.3.0 for the "before" columns |

The two tools answer different questions, so neither number below is a score
for "which is better". The official suite is the referee the MCP project uses
to grade its SDKs: it ships its own test fixtures and asks whether an
implementation behaves correctly *when it has them*. Sentinel grades any server
as it is, from the wire. The interesting results are where they disagree.

## Result 1 — the official suite found six real defects Sentinel had missed

Run against Sentinel's own conformant fixture, the official suite reported six
scored failures that were not about missing fixtures. All six were real, and all
six trace back to one misreading: Sentinel treated `server/discover` as exempt
from version negotiation, following the release candidate. The final text says
a server MAY answer it with `UnsupportedProtocolVersionError` and requires
`protocolVersion` on every request.

| Official check | What was wrong | Fixed in |
|---|---|---|
| `sep-2575-http-server-header-mismatch-400` | discover with header/body version mismatch was served | fixture, broker |
| `sep-2575-request-meta-invalid-missing-protocol-version` | discover with no version was served | fixture, broker |
| `sep-2575-http-server-meta-invalid-400` | same request, HTTP 200 instead of 400 | fixture, broker |
| `sep-2575-http-server-unsupported-version-400` | `-32022` sent with HTTP 200 | fixture |
| `sep-2575-server-unsupported-version-error` | `-32022` data used `supportedVersions`; the error schema says `supported` and `requested` | fixture, broker |
| `localhost-host-valid-accepted` | fixture refused an `Origin` naming itself | fixture |

Plus one in a scenario the suite does not yet score: Mcp-Name compared with its
surrounding whitespace (`sep-2243-server-accepts-whitespace-header-value`).

Sentinel now has rules for all of it — `unsupported-version-error-shape` and
`header-values-compared-without-surrounding-whitespace` are new, and
`discover-without-negotiated-version` is deprecated in favour of the first.

**After:** the official suite reports **0** core failures on the corrected
fixture. Its remaining 65 failing checks are all either the suite's own fixtures
(29: the server has no tool named `test_simple_text`, `slow_compute`,
`test_input_required_result_multi_round` …) or unscored extension and pending
scenarios (36).

## Result 2 — Sentinel had four false positives on the reference server

Sentinel 0.3.0 reported 5 MUST and 1 SHOULD failures on the official reference
server, which the official suite passes. Checked one by one against the spec
text and the wire, four were Sentinel's mistakes:

| Sentinel 0.3.0 finding | Why it was wrong | Fix |
|---|---|---|
| `discover-without-negotiated-version` | the rule itself contradicts the final text | deprecated, superseded |
| `missing-protocol-version-rejected` | the probe also dropped the version header, and a dual-era server may treat that as a legacy client | keeps the header; accepts `-32602` or `-32020` with HTTP 400 |
| `list-changed-advertised-truthfully` | the probe sent `subscriptions/listen` without the required `notifications` filter | sends a real filter and reads the stream's first message (the acknowledgement) |
| `get-delete-405` (SHOULD) | the 405 is asked only of servers supporting this revision alone; the reference server is dual-era | not-applicable when the server completes a legacy `initialize` |

## Result 3 — two real defects in the reference server that the official suite does not check

With those fixed, Sentinel 0.4.0 reports exactly **2 MUST failures** on the
reference server. Both reproduce with a single `curl`:

1. **`invalid-origin-rejected`.** A request with `Origin: https://sentinel-rebinding-probe.invalid`
   is served with HTTP 200. The spec: if the `Origin` header is present and
   invalid, servers MUST respond 403. The server validates `Host` instead — a
   foreign `Host` gets 403, a foreign `Origin` with `Host: localhost` gets 200 —
   and the suite's rebinding checks send a foreign `Host`, so they pass. The
   practical risk is small (classic DNS rebinding carries the attacker's `Host`,
   which is refused, and a cross-origin JSON POST needs a CORS preflight this
   server does not grant), but it is a MUST the server does not meet.
2. **`malformed-json-is-parse-error`.** A body that is not valid JSON gets an
   HTML error page (`Content-Type: text/html`), not a JSON-RPC `-32700` parse
   error.

(It also reports one `SENTINEL/STYLE` opinion — tools not sorted by name — which
is beyond the spec and does not affect the conformance gate.)

## Summary

| Server | Official suite — core failures | Sentinel — MUST failures |
|---|---:|---:|
| Official reference server | 0 (30 checks failing, all unscored extension) | 0.3.0: 5 (3 false) → **0.4.0: 2, both real** |
| Sentinel conformant fixture | before: 6 real → **after: 0** (+29 fixture, 36 unscored) | 0 |
| Sentinel non-conformant fixture (39 seeded violations) | 55 | 34 MUST + 4 SHOULD + 1 beyond-spec = 39/39 seeded |

## How failures are classified

`benchmarks/official-suite/compare.py` puts every failing official check in one
bucket using the suite's own output: **unscored** if the run log marks the
scenario `(extension)` or `(pending)`; **fixture** if the message says the server
lacks something the suite ships for its reference server, or the check is listed
in `FIXTURE_CHECKS` with the reason; **core** otherwise. The patterns are the
whole of the judgement — delete one and re-run if you disagree with it.
