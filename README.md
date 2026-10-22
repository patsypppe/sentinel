# Sentinel

**Sentinel checks whether an MCP server follows the MCP specification.**

[MCP](https://modelcontextprotocol.io) (Model Context Protocol) is how AI apps such as Claude
connect to tools. A tool is exposed by an *MCP server*, and the server has to follow a rulebook, the
MCP specification. Servers often get parts of it wrong, and then they break or misbehave with some
clients. Sentinel finds those mistakes.

You give it a server's URL. It sends the server test requests, checks each answer against the
rulebook, and prints a pass/fail list. Every failure says what it saw, what to change, and which
page of the spec the rule comes from.

## Try it in two minutes

This repo includes two fake servers to practise on: one with deliberate mistakes, one that follows
the rules. You need [uv](https://docs.astral.sh/uv/) and Python 3.12+.

```bash
git clone https://github.com/patsypppe/sentinel && cd sentinel

# 1. start the two practice servers (leave this running)
uv run sentinel fixture serve --profile nonconformant --port 9000 &
uv run sentinel fixture serve --profile conformant    --port 9001 &

# 2. scan the one with mistakes: it fails
uv run sentinel scan --endpoint http://localhost:9000/mcp --gate must
echo "exit code: $?"          # 1 = at least one MUST rule failed

# 3. scan the correct one: it passes
uv run sentinel scan --endpoint http://localhost:9001/mcp --gate must
echo "exit code: $?"          # 0 = no MUST rule failed
```

A failure looks like this:

```
FAIL  MCP/2026-07-28/MUST/cacheable-results-carry-ttl
      observed:    4 of 4 list results omit ttlMs: ['server/discover', 'tools/list', ...]
      remediation: Add ttlMs to every list and read result. ...
      spec:        https://modelcontextprotocol.io/specification/2026-07-28/changelog#minor-changes
```

## Scan your own server

No clone needed:

```bash
uvx --from "git+https://github.com/patsypppe/sentinel@main#subdirectory=harness" \
  sentinel scan --endpoint https://your-server.example/mcp --gate must
```

If the server needs a login token, add `--token "$TOKEN"`. Only scan servers you own or have
permission to test.

## How it works

1. **It speaks plain HTTP.** Sentinel sends raw JSON-RPC requests itself and uses no MCP library. A
   library would quietly fix a server's mistakes, such as adding a missing header, and hide them.
   It works on a server written in any language.
2. **Each rule is a small test.** A rule sends one or more requests, reads the answer, and decides
   PASS, FAIL or something else. The rules live in
   [`harness/src/sentinel/catalog/`](harness/src/sentinel/catalog/), and each one names the spec
   sentence it comes from.
3. **It never guesses.** Some requirements cannot be checked from outside, for example "does the
   server write an audit log?". Those are reported as `INDETERMINATE` and are never counted as a pass.
4. **The exit code is the verdict.** `0` means no MUST rule failed and `1` means at least one did,
   so CI can fail a build on it.

Terms: **MUST** rules are required, and a failure fails the gate. **SHOULD** rules are
recommendations, so they are reported but never fail the gate. The rule names carry a date,
`2026-07-28`, because that is the spec revision they were written against.

## Test Sentinel itself

```bash
make check     # lint, type-check and the test suite (needs Go 1.23+, Python 3.12+, uv)
```

The tests scan the two practice servers and expect the bad one to fail and the good one to pass, so
a rule that stops catching its mistake fails the build.

## Going further

- [`docs/USING.md`](docs/USING.md): waivers, baselines, CI setup, report formats, many servers at once
- [`docs/OVERVIEW.md`](docs/OVERVIEW.md): the full project overview, including the reference server (`broker/`), the Go server kit (`mcp/`) and the history service (`fleet/`)
- [`docs/MIGRATION.md`](docs/MIGRATION.md): what changed in the current MCP spec
- [`CHANGELOG.md`](CHANGELOG.md)

MIT licensed.
