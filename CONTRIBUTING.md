# Contributing to toolgauge

Thanks for helping. toolgauge checks MCP servers against the specification, so most changes are
one of four kinds: a new or corrected rule, a new server in a benchmark, a fix to how a finding is
reported, or documentation. Each is described below with the exact files to touch.

## Pick something to work on

The [issue tracker](https://github.com/patsypppe/toolgauge/issues) holds scoped tasks, each with what to
change and how to know it is done.

- `good first issue`: small and self-contained, a few hours at most. A good place to start.
- `help wanted`: larger, or needing judgement about the specification.
- Area labels (`area: rules`, `area: benchmarks`, `area: precision`, `area: docs`, `area: transport`)
  say which part of the code is involved.

Comment on an issue before starting so two people do not do the same work. If an issue is unclear,
ask in the issue; that is a useful contribution too.

## Set up

You need Python 3.12 or newer and [uv](https://docs.astral.sh/uv/). Go 1.23 or newer is only needed
for the Go parts (`broker/`, `mcp/`, `fleet/`); most harness work never touches them.

```bash
git clone https://github.com/patsypppe/toolgauge
cd toolgauge
uv sync
uv run toolgauge demo          # should print one FAIL verdict and one PASS verdict
```

## Test

Python only (what most changes need):

```bash
uv run ruff format .           # format
uv run ruff check .            # lint
uv run mypy                    # type-check (strict)
uv run pytest tests -m unit -q -n auto
```

Everything, including Go (what CI runs):

```bash
make check
```

All of it must pass before a pull request is merged. CI runs the same commands on every push.

## Where things live

| Path | What it is |
|---|---|
| `harness/src/toolgauge/catalog/must/`, `should/` | Rules that restate the MCP specification (`MCP/<revision>/MUST/...`, `SHOULD/...`) |
| `harness/src/toolgauge/catalog/beyond/` | Rules that go beyond the spec (`TOOLGAUGE/STYLE`, `SECURITY`, `OPS`) |
| `harness/src/toolgauge/probe/` | The HTTP and stdio transports. Requests are built by hand on purpose; no MCP SDK |
| `harness/src/toolgauge/report/` | Text, JSON, SARIF, HTML, JUnit and Markdown output |
| `fixtures/server/` | Practice servers: `nonconformant` (seeded violations), `conformant`, `partial` |
| `tests/harness/` | Tests. Most run the practice servers in-process |
| `benchmarks/` | Measurements against servers this project did not write |

## Adding or changing a rule

1. **Find the sentence first.** A spec rule restates a sentence in the specification. Quote it in the
   pull request, with the page and heading. If you cannot find one, the rule belongs in `beyond/` with a
   `rationale`, not in the spec namespace.
2. **Match the severity to the text.** MUST in the spec is a `Severity.MUST` rule; SHOULD is SHOULD.
3. **Never fail what you cannot see.** If the wire cannot tell a violation from an allowed behaviour,
   return `RuleResult.indeterminate(...)` and say why. A false FAIL costs more than a missed one.
4. **Rule ids are permanent.** Never rename or delete one. To change a rule's meaning or severity, set
   `deprecated_in` and `superseded_by` on the old rule and add a new one.
5. **Test both directions.** The `nonconformant` fixture should fail it (tag the violation with a
   `# VIOLATES <rule id>` comment and add the id to `SEEDED_VIOLATIONS`), and the `conformant` fixture
   should pass it. `tests/harness/test_fixture_oracle.py` checks both.

## Adding a server to a benchmark

`benchmarks/popular_servers.py` has a `SERVERS` list. Add an entry with the start command from the
server's README (`npx -y ...` or `uvx ...`) and a dummy value for any credential it needs just to
start. Run `uv run python benchmarks/popular_servers.py`, then `uv run python benchmarks/chart.py`, and
commit the regenerated `POPULAR_SERVERS.md`, `.json` and `.svg`. Never add a server's real credentials.

## Checking precision

A finding is only useful if it is right. `benchmarks/PRECISION.md` records hand-checked samples. To add
one: draw findings at random with a fixed seed, read each against the specification text or the tool's
actual description, and record each verdict (correct, low value or wrong) with a one-line reason. Wrong
verdicts are the most valuable result: open an issue for each.

## Sending a change

- One change per pull request, on a branch.
- Commit messages: `<type>: <description>`, where type is one of `feat`, `fix`, `refactor`, `docs`,
  `test`, `chore`, `perf`, `ci`.
- In the description, say what changed, why, and how you tested it. For a rule, quote the spec sentence.
- Do not scan servers you do not own or have permission to test, and never publish another project's
  findings before its maintainers have seen them.

## Code of conduct

Be kind and assume good faith. Disagreements about what the specification means are normal; settle
them by quoting the text.
