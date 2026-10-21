# Sentinel — MCP conformance

A conformance harness for **MCP `2026-07-28`**, published as `sentinel-mcp-conformance`.

Scans any MCP server, grades it against the normative requirements with a spec citation per rule,
reports which MUSTs it **cannot** verify black-box rather than scoring them as passes, and
inventories which deprecated features the target still depends on with their earliest removal dates.

```bash
uvx sentinel-mcp-conformance scan --endpoint http://localhost:8080/mcp --gate must
sentinel scan --endpoint https://someone-elses.example/mcp --safe   # never invokes a non-read-only tool
sentinel registry-scan --out-dir scan                               # every remote server in the MCP registry
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

Responses framed as `text/event-stream` are read the same as bare JSON: the transport allows both,
and grading an SSE reply as "no JSON-RPC response" would be the scanner's bug, not the server's.

See the repository root for the full project, including `broker`, the server this harness grades.
