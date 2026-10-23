# MCP registry conformance scan — 2026-10-23

Sentinel `0.4.0` graded every remote server in the [official MCP registry](https://registry.modelcontextprotocol.io) against MCP `2026-07-28`, in safe mode (no tool invoked unless annotated read-only, one connection per host, no retries).

| | Endpoints | % |
|---|---:|---:|
| Scanned | 15451 | |
| Speak `2026-07-28` | 2263 | 14.6 |
| Only speak the old `2025-11-25` handshake | 5522 | 35.7 |
| Require credentials before answering | 6044 | 39.1 |
| Unreachable or erroring | 1213 | 7.9 |
| Answer, but neither handshake | 409 | 2.6 |

Of the 2263 servers speaking `2026-07-28`, **13** (0.6%) pass every MUST rule Sentinel can verify from the wire. Median MUST failures per server: 3.0.

## Most-failed MUST rules

| Rule | Servers | % of graded |
|---|---:|---:|
| `MCP/2026-07-28/MUST/missing-protocol-version-rejected` | 2204 | 97.4 |
| `MCP/2026-07-28/MUST/invalid-origin-rejected` | 1399 | 61.8 |
| `MCP/2026-07-28/MUST/protocol-version-header-body-mismatch-rejected` | 898 | 39.7 |
| `MCP/2026-07-28/MUST/missing-client-capabilities-rejected` | 749 | 33.1 |
| `MCP/2026-07-28/MUST/unknown-method-http-404` | 737 | 32.6 |
| `MCP/2026-07-28/MUST/unsupported-version-rejected` | 686 | 30.3 |
| `MCP/2026-07-28/MUST/header-body-mismatch-rejected` | 550 | 24.3 |
| `MCP/2026-07-28/MUST/mcp-method-header-required` | 526 | 23.2 |
| `MCP/2026-07-28/MUST/unknown-method-is-method-not-found` | 509 | 22.5 |
| `MCP/2026-07-28/MUST/resource-not-found-is-invalid-params` | 426 | 18.8 |
| `MCP/2026-07-28/MUST/protocol-version-header-required` | 366 | 16.2 |
| `MCP/2026-07-28/MUST/cacheable-results-carry-scope` | 346 | 15.3 |
| `MCP/2026-07-28/MUST/cacheable-results-carry-ttl` | 252 | 11.1 |
| `MCP/2026-07-28/MUST/mcp-name-header-required` | 205 | 9.1 |
| `MCP/2026-07-28/MUST/discover-reports-supported-versions` | 172 | 7.6 |

Per-server results are deliberately not published: findings go to each server's maintainer first.
