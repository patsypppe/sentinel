/** §5: retired rules next to their successors, from a replay scan. */
import { h, mount, replaceContent } from "./dom.js";
import { outcomeLabel, shortRuleId } from "./model.js";

// Quoted from README.md, "Rule lifecycle". The table there is the source of truth.
const REASONS = {
  "MCP/2026-07-28/MUST/server-info-echoed":
    "The spec marks serverInfo Required: No. Omitting it costs you cache keys and attribution; it does not make you non-conformant.",
  "MCP/2026-07-28/MUST/tools-list-is-deterministic":
    "“Servers SHOULD return tools in a deterministic order.” The MUST in the same paragraph is a different property — the set MUST NOT vary per-connection — now checked by MUST/tools-list-connection-independent.",
  "MCP/2026-07-28/SHOULD/tools-sorted-by-name":
    "The specification asks for a deterministic order and never for a sorted one, so a stable unsorted manifest conforms fully. It is still a good idea, so it moved to the beyond-spec namespace rather than being deleted.",
};

function idCell(label, id, outcome) {
  return h("div", { class: "life__cell" },
    h("p", { class: "life__label", text: label }),
    h("p", { class: "life__id mono", text: shortRuleId(id) }),
    outcome ? h("span", { class: `tag tag--${outcome}`, text: outcomeLabel(outcome) }) : null,
  );
}

export function renderLifecycle(data) {
  const current = new Map(data.nonconformant.findings.map((f) => [f.ruleId, f]));
  const retired = data.replay.findings.filter((f) => f.deprecated);
  replaceContent(mount("lifecycle"),
    h("ol", { class: "life" },
      retired.map((f) =>
        h("li", { class: "life__row" },
          idCell("deprecated in 0.2.0, still answers as it always did", f.ruleId, f.outcome),
          h("span", { class: "life__arrow", attrs: { "aria-label": "superseded by" }, text: "→" }),
          idCell("published successor, new ID", f.supersededBy, current.get(f.supersededBy)?.outcome),
          REASONS[f.ruleId] ? h("p", { class: "life__why", text: REASONS[f.ruleId] }) : null,
        ),
      ),
    ),
  );
}
