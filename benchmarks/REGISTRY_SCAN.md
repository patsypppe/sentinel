# Registry scan

Two runs of the `registry-scan` workflow on GitHub Actions, aggregate only (per-server findings go to each
maintainer first). They answer different questions and the second **supersedes the rule-level numbers of
the first**.

## 1. Where the registry is today (all 15,451 endpoints, 2026-10-23)

Classification does not depend on the rules, so these numbers stand:

| | Endpoints | % |
|---|---:|---:|
| Scanned | 15451 | |
| Speak `2026-07-28` | 2263 | 14.6 |
| Only speak the old `2025-11-25` handshake | 5522 | 35.7 |
| Require credentials before answering | 6044 | 39.1 |
| Unreachable or erroring | 1213 | 7.9 |
| Answer, but neither handshake | 409 | 2.6 |

## 2. How the servers on the new revision fare (4,000-endpoint sample, corrected rules, 2026-10-24)

The first run's rule-level results were wrong in two ways, found by reading the aggregate of a sample:
537 of 572 failures of one rule were "request served" (allowed for a server that also serves
previous-revision clients), and many failures were HTTP 429/401 answers (the scan being rate-limited or
refused, not a finding). Both are fixed (`unusable_reason()`, and "served" is INDETERMINATE), and the same
sample was rerun. The first run reported 1 of 583 passing every rule; the corrected sample reports 95 of 590.

The sample is the first 4,000 endpoints in registry listing order, not a random draw: its classification
shares differ from run 1 (for example 25.9% old-handshake versus 35.7%), so use run 1 for adoption and this
for rule behaviour, and treat the rule percentages as indicative.

Sentinel `0.4.0` graded every remote server in the [official MCP registry](https://registry.modelcontextprotocol.io) against MCP `2026-07-28`, in safe mode (no tool invoked unless annotated read-only, one connection per host, no retries).

| | Endpoints | % |
|---|---:|---:|
| Scanned | 4000 | |
| Speak `2026-07-28` | 590 | 14.8 |
| Only speak the old `2025-11-25` handshake | 1034 | 25.9 |
| Require credentials before answering | 1819 | 45.5 |
| Unreachable or erroring | 462 | 11.6 |
| Answer, but neither handshake | 95 | 2.4 |

Of the 590 servers speaking `2026-07-28`, **95** (16.1%) pass every MUST rule Sentinel can verify from the wire. Median MUST failures per server: 1.0.

## Most-failed MUST rules

| Rule | Servers | % of graded |
|---|---:|---:|
| `MCP/2026-07-28/MUST/invalid-origin-rejected` | 309 | 52.4 |
| `MCP/2026-07-28/MUST/cacheable-results-carry-scope` | 156 | 26.4 |
| `MCP/2026-07-28/MUST/discover-reports-supported-versions` | 119 | 20.2 |
| `MCP/2026-07-28/MUST/protocol-version-header-body-mismatch-rejected` | 101 | 17.1 |
| `MCP/2026-07-28/MUST/missing-client-capabilities-rejected` | 89 | 15.1 |
| `MCP/2026-07-28/MUST/unknown-method-http-404` | 85 | 14.4 |
| `MCP/2026-07-28/MUST/mcp-method-header-required` | 63 | 10.7 |
| `MCP/2026-07-28/MUST/unsupported-version-rejected` | 61 | 10.3 |
| `MCP/2026-07-28/MUST/cacheable-results-carry-ttl` | 60 | 10.2 |
| `MCP/2026-07-28/MUST/notification-not-answered-with-a-result` | 56 | 9.5 |
| `MCP/2026-07-28/MUST/header-body-mismatch-rejected` | 43 | 7.3 |
| `MCP/2026-07-28/MUST/result-type-present` | 37 | 6.3 |
| `MCP/2026-07-28/MUST/resource-not-found-is-invalid-params` | 36 | 6.1 |
| `MCP/2026-07-28/MUST/mcp-name-header-required` | 28 | 4.7 |
| `MCP/2026-07-28/MUST/missing-protocol-version-rejected` | 24 | 4.1 |

## What the failing servers actually answered

- `MCP/2026-07-28/MUST/invalid-origin-rejected`: request was served: 309
- `MCP/2026-07-28/MUST/cacheable-results-carry-scope`: other: 156
- `MCP/2026-07-28/MUST/discover-reports-supported-versions`: other: 119
- `MCP/2026-07-28/MUST/protocol-version-header-body-mismatch-rejected`: request was served: 72, HTTP 400, code -32600: 27, HTTP 400, code -32022: 1, HTTP 400, code -32000: 1
- `MCP/2026-07-28/MUST/missing-client-capabilities-rejected`: request was served: 69, HTTP 400, code -32600: 15, HTTP 200, code -32602: 2, HTTP 400, code -32000: 2, HTTP 400, code -32021: 1

Per-server results are deliberately not published: findings go to each server's maintainer first.
Reading it: `invalid-origin-rejected` is the standout (52% serve a request carrying an impossible `Origin`).
The specification says a server MUST reject that, but a public server meant to be called from browsers may
allow any origin on purpose, so it is a spec violation more than a bug. `cacheable-results-carry-scope` and
`discover-reports-supported-versions` are classified "other": the server answered but the field is missing
or empty. I have not hand-verified a sample of these findings, so the rule-level percentages are Sentinel's
reading, not ground truth.
