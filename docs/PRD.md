# SN-PRD-001 — not included in this repository

`SN-HND-001` (`docs/HANDOFF.md`) implements the MVP tier of **SN-PRD-001**, the Sentinel product
requirements document. That PRD is an upstream planning artifact and was not supplied with this
implementation handoff, so it is deliberately **not** reproduced here rather than reconstructed
from inference.

Everything the implementation actually depends on was restated inside the handoff and is
authoritative in this repository:

| PRD reference | Where it lives here |
|---|---|
| §3.2 / Appendix C — the MVP capability set | `docs/HANDOFF.md` §3.1 (the 15 `SN-CAP` rows) |
| §6.2 — database schema | `broker/internal/store/migrations/` |
| §7.4 — configuration keys | `broker/internal/config/config.go` |
| Appendix C — demo script | `docs/HANDOFF.md` §13, `docs/demo/` |

## Recorded divergence

`docs/HANDOFF.md` §3.3 adds one MVP-only configuration key not present in SN-PRD-001 §7.4:

**`mrtr.replay_window`**, distinct from `mrtr.flow_ttl`.

- `flow_ttl` bounds how long a flow may sit **awaiting input**.
- `replay_window` bounds how long a **consumed** flow retains its recorded result for idempotent replay.

Collapsing them into one value forces a choice between a short approval window and a long replay
guarantee; the design wants a short window with a long guarantee. **This should be folded back into
SN-PRD-001 §7.4.**

## Recorded divergence — corrected

`docs/HANDOFF.md` §8.2 stated a header rule the MCP `2026-07-28` specification does not make:

**`Mcp-Name` must equal "the tool, prompt or resource name where the method takes one, *and the
method name otherwise*".**

The "otherwise" clause has no source. The specification's Standard Request Headers table gives
`Mcp-Name` the source field `params.name` or `params.uri` and the required scope "`tools/call`,
`resources/read`, `prompts/get` requests"; "All requests" is `Mcp-Method`'s row. A method with
neither params field has no corresponding body value, so there is nothing a header could be matched
against — and the specification's own validation rule is that a server **MUST** reject "requests
where the values specified in the headers do not match the corresponding values in the request
body".

The clause was load-bearing in both products, in opposite directions:

- **The broker** required `Mcp-Name` on every method. A conformant client that sent none received
  `-32020` on its first `tools/list` — a reference implementation demanding a header the
  specification does not define for the method.
- **The harness probe** sent the method name as `Mcp-Name` on every non-name-bearing request. A
  server strict enough to reject that header would have had every probe request refused, and the
  harness would have graded a conformant server as broken.

Both were corrected together in WP-16, because changing either alone breaks the demo. The catalog
gained `MCP/2026-07-28/MUST/mcp-name-not-required-where-undefined` (`introduced_in` 0.2.0) so the
over-validation half is a finding rather than a blind spot, and the non-conformant fixture seeds it.
**This should be folded back into SN-HND-001 §8.2**, which now carries the correction inline.

## Precedence

On any question of protocol behavior, the
[MCP `2026-07-28` specification](https://modelcontextprotocol.io/specification/2026-07-28/)
supersedes both the PRD and the handoff.
