# Benchmarks

Two measurements against servers this project did not write. Both are reproducible; each prints
a table and writes it next to the script.

| | Script | Result file |
|---|---|---|
| Does Sentinel catch violations that the MCP maintainers labelled? | `official_negatives.py` | [`RESULTS.md`](RESULTS.md) |
| What does Sentinel report on servers built with the official SDKs? | `sdk_readiness.py` | [`SDK_RESULTS.md`](SDK_RESULTS.md) |

```bash
git clone https://github.com/modelcontextprotocol/conformance && cd conformance
npm ci && (cd examples/servers/typescript && npm ci) && cd -
uv run python benchmarks/official_negatives.py --conformance ../conformance
uv run python benchmarks/sdk_readiness.py      --conformance ../conformance
```

Measured against `modelcontextprotocol/conformance` at commit `c37eec8`, run on 2026-10-22; the SDK numbers are for `mcp` 2.3.0 from PyPI.

## How to read the numbers

**Answer key.** The broken servers in `modelcontextprotocol/conformance` each carry a header
comment naming their one violation. Those labels were written by the MCP maintainers for their
own test suite. Each label is mapped to the Sentinel rule that should catch it (the `LABELS` table at the top of
the script, taken from the fixtures' own comments), and a rule counts as caught only if it FAILed.
Be aware that this is not a blind test: the rules existed before these fixtures were run, but the
same person looked at the fixtures while writing the mapping, and no rule was changed to improve
these results. One change *was* made from the SDK scan: the stub-description threshold went from
20 to 12 characters after "Add two numbers." was flagged, which is a false positive.

**Misses are reported, not tuned away.** Of the 8 labelled violations, 2 were missed:

- one broken server speaks only the *previous* MCP revision, so none of Sentinel's rules (which test
  the current one) can run against it. Sentinel now says so at the top of the report;
- one refuses every probe with HTTP 500, so Sentinel reports INDETERMINATE for the Origin rule
  rather than guess. That is the designed behaviour (an unverifiable requirement is never a pass),
  and it costs recall.

One labelled violation (JSON Schema 2020-12 keywords stripped from a schema) has no Sentinel rule at
all. That is a coverage gap.

## Where Sentinel is stricter than the official suite, on purpose

- **Error codes for rejected headers.** The specification text says a server rejecting a request for a
  bad or missing standard header MUST answer HTTP 400 *and* JSON-RPC code `-32020`. The official suite
  treats the code as a SHOULD for standard headers. Sentinel follows the spec text, so a server
  that answers 400 with some other code (the Python SDK answers `-32600`) FAILs here and passes there.
  Both readings are written down; neither is hidden.
- **Origin validation and the `Mcp-Method` / `Mcp-Name` headers.** The spec says MUST. The official
  suite's own header scenarios are still marked *pending*, and its reference server does not enforce
  them either.

## Limits

- Public servers on the internet were not scanned: the environment these were produced in blocks
  outbound connections to them. The broken fixtures and SDK servers run on localhost.
- Eight labelled violations is a small sample. The result is "it catches what it was built to catch
  and says where it cannot", not a precision/recall figure to quote to three digits.
