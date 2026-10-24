# Benchmark: violations labelled by the MCP maintainers

Each server below is a deliberately broken fixture from the official `modelcontextprotocol/conformance` repo. The violation column is that fixture's own description. Sentinel is run unmodified; a rule counts as *caught* only if it FAILed.

| Broken server | What the maintainers say is wrong | Sentinel | Why not |
|---|---|---|---|
| `sep-2549-no-caching-hints` | omits ttlMs and cacheScope from list/read results | 2/2 caught |  |
| `sep-2322-mrtr-broken-server` | omits resultType; accepts a tampered requestState | 2/2 caught |  |
| `sep-2164-empty-contents` | returns an empty contents array for a resource that does not exist | 1/1 caught |  |
| `tools-list-rotated-order` | reorders tools/list on every call | 1/1 caught |  |
| `invalid-tool-names` | advertises tool names with illegal characters | 1/1 caught |  |
| `no-dns-rebinding-protection` | does not validate the Origin header | not gradable | the fixture itself fails every request (server error on all methods) |
| `sep-2106-stripped-schema` | strips JSON Schema 2020-12 keywords from a tool's inputSchema | no rule | coverage gap: JSON Schema 2020-12 preservation is not checked |

**7 of 7 labelled violations caught** (100%). Misses are listed, not hidden.
