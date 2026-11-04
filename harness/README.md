# toolgauge

**Check whether an MCP server follows the MCP specification, and whether its tools are documented well
enough for a model to use them.**

[MCP](https://modelcontextprotocol.io) (Model Context Protocol) is how AI apps connect to tools.
toolgauge sends a server real requests, checks every answer against the specification, and lints its
tool descriptions. Each finding says what it saw, what to change, and which part of the spec it comes from.

## Install

```bash
pip install toolgauge          # or: pipx install toolgauge
```

Or run it without installing: `uvx toolgauge demo`. Needs Python 3.12 or newer.

## Use

```bash
toolgauge demo                                                     # scan two practice servers, see the difference
toolgauge lint --command "npx -y @modelcontextprotocol/server-filesystem /tmp"   # lint a stdio server
toolgauge scan --endpoint https://your-server.example/mcp --gate must            # grade an HTTP server
toolgauge scan --endpoint https://your-server.example/mcp --format sarif --out scan.sarif
```

`--gate must` exits **1** if a required rule fails and **0** otherwise, so it drops into CI. A requirement
that cannot be checked from outside the server is reported as `INDETERMINATE`, never as a pass. Use
`--safe` on a server you do not own: it never invokes a tool that is not annotated read-only.

## What it has measured

Every remote server in the official MCP registry (15,451 endpoints), 28 widely used published servers,
and the MCP maintainers' own broken test servers, with hand-checked precision samples and a comparison
against Cisco's mcp-scanner. Details and methodology:
[github.com/patsypppe/toolgauge/tree/main/benchmarks](https://github.com/patsypppe/toolgauge/tree/main/benchmarks).

## Links

- Source, issues and contributing guide: [github.com/patsypppe/toolgauge](https://github.com/patsypppe/toolgauge)
- Usage guide (waivers, baselines, CI, report formats): [docs/USING.md](https://github.com/patsypppe/toolgauge/blob/main/docs/USING.md)
- Changelog: [CHANGELOG.md](https://github.com/patsypppe/toolgauge/blob/main/CHANGELOG.md)

MIT licensed.
