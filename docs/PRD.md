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

## Precedence

On any question of protocol behavior, the
[MCP `2026-07-28` specification](https://modelcontextprotocol.io/specification/2026-07-28/)
supersedes both the PRD and the handoff.
