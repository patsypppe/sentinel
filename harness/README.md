# sentinel

A conformance harness for **MCP `2026-07-28`**.

Scans any MCP server, grades it against the normative requirements with a spec citation per rule,
reports which MUSTs it **cannot** verify black-box rather than scoring them as passes, and
inventories which deprecated features the target still depends on with their earliest removal dates.

```bash
uv run sentinel scan --endpoint http://localhost:8080/mcp --gate must --format sarif --out scan.sarif
uv run sentinel deprecations --endpoint http://localhost:8080/mcp --as-of 2026-09-23
uv run sentinel catalog validate
```

`scan --gate must` exits **1** if any MUST rule FAILs and **0** otherwise. `INDETERMINATE` never
fails a gate but is always printed. Every other subcommand reserves non-zero for harness errors, so
CI can distinguish "the server is wrong" from "the scanner broke".

The probe is a deliberately literal MCP client — requests are built by hand from the specification,
never through an SDK, because an SDK that helpfully adds `Mcp-Method` would make the rule requiring
`Mcp-Method` untestable.

See the repository root for the full project, including `broker`, the server this harness grades.
