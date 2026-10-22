# Citations that are not yet anchored

Every `MCP/` rule cites the page of the 2026-07-28 specification it restates. Most cite a
heading anchor. **Eleven cite the page only**, because the anchors for those requirements could
not be confirmed against the published specification when the rules were written (the
specification host was unreachable from the environment that wrote them). A citation to an
anchor that does not exist sends a reader to the top of a page while implying the specification
says something it does not, so the rules point at the page and nothing finer.

This is the honest state, and it is a to-do:

| Rule | Cites | To confirm |
|---|---|---|
| `MUST/x-mcp-header-not-empty` | `basic/transports/streamable-http` | the section on `x-mcp-header`, and that this is the right page for it |
| `MUST/x-mcp-header-token-syntax` | `basic/transports/streamable-http` | as above |
| `MUST/x-mcp-header-no-control-characters` | `basic/transports/streamable-http` | as above |
| `MUST/x-mcp-header-case-insensitively-unique` | `basic/transports/streamable-http` | as above |
| `MUST/x-mcp-header-primitive-types-only` | `basic/transports/streamable-http` | as above, and the exact set of permitted types |
| `MUST/tools-declare-valid-input-schema` | `server/tools` | the tool definition section |
| `SHOULD/tool-names-well-formed` | `server/tools` | the naming guidance, and its length and character limits |
| `SHOULD/tool-names-unique-within-server` | `server/tools` | the naming guidance |
| `MUST/tampered-requeststate-rejected` | `basic/patterns/mrtr` | the section on treating `requestState` as untrusted |
| `MUST/input-required-carries-requests-or-state` | `basic/patterns/mrtr` | the `InputRequiredResult` definition |
| `MUST/input-requests-respect-declared-capabilities` | `basic/patterns/mrtr` | the capability rules for input requests |

Until each is confirmed, treat the rule's *remediation text* as this project's reading of the
specification, not as a quotation of it. `tests/harness/test_citations.py` only allows a page or
anchor on its allowlist, and `tests/harness/test_citation_notes.py` fails if this file stops
matching the catalog, so promoting a rule to an anchor means editing both.

## Confirming one

1. Open the page and find the heading the requirement sits under.
2. Add the page and anchor to `KNOWN` in `tests/harness/test_citations.py`.
3. Change the rule's `citation=` to `{PAGE}#anchor`.
4. Delete its row here.

## Rules that read the wire, not the specification

Two decisions in the MRTR rules are deliberate and worth stating. They say nothing about the
*shape* of `inputRequests`, because that is a field the server fills for its own client and
grading its internal structure from outside would be grading a guess. And
`input-requests-respect-declared-capabilities` returns `NOT_APPLICABLE`, never a pass, when no
tool asks for input: nothing was observed, so nothing was verified.
