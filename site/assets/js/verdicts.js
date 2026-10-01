/** §1: one column per scanned server, with every rule drawn as a cell. */
import { h, mount, replaceContent } from "./dom.js";
import { TARGETS, sortFindings, outcomeLabel } from "./model.js";

const COUNT_KEYS = [
  ["pass", "pass"],
  ["fail", "fail"],
  ["indeterminate", "indeterminate"],
  ["not_applicable", "n/a"],
];
// Short column labels for the figure row; the full word is in the summary line.
const FIG_LABEL = { pass: "pass", fail: "fail", indeterminate: "indet.", not_applicable: "n/a" };

function summaryLine(label, counts, withIndeterminate) {
  const parts = COUNT_KEYS.filter(([k]) => withIndeterminate || k !== "indeterminate").map(
    ([k, word]) => `${counts[k]} ${word}`,
  );
  return `${label}: ${parts.join(", ")}`;
}

function ruleStrip(findings) {
  // Decorative: the same numbers are in the figures and the summary line.
  return h(
    "div",
    { class: "strip", attrs: { "aria-hidden": "true" } },
    sortFindings(findings).map((f) =>
      h("span", { class: `strip__cell strip__cell--${f.outcome}`, attrs: { title: `${outcomeLabel(f.outcome)} · ${f.ruleId}` } }),
    ),
  );
}

function verdictColumn(target, scan, exitCode, onOpen) {
  const must = scan.summary.must;
  const failed = exitCode === 1;
  return h(
    "article",
    { class: `verdict ${failed ? "verdict--fail" : "verdict--pass"}`, attrs: { "aria-labelledby": `v-${target.key}` } },
    h("header", { class: "verdict__head" },
      h("h3", { class: "verdict__name", attrs: { id: `v-${target.key}` }, text: target.label }),
      h("p", { class: "verdict__role", text: target.role }),
    ),
    h("p", { class: "verdict__exit" },
      h("span", { class: "verdict__code", text: `exit ${exitCode}` }),
      h("span", { text: failed ? "fails the MUST gate" : "passes the MUST gate" }),
    ),
    h("p", { class: "verdict__caption", text: "MUST-severity rules" }),
    h("dl", { class: "verdict__figures" },
      COUNT_KEYS.map(([k, word]) =>
        h("div", { class: `fig fig--${k}` },
          h("dt", {}, k === "indeterminate" ? h("abbr", { attrs: { title: word }, text: FIG_LABEL[k] }) : FIG_LABEL[k]),
          h("dd", { text: must[k] }),
        ),
      ),
    ),
    ruleStrip(scan.findings),
    h("pre", { class: "verdict__line", attrs: { "aria-label": "Summary as printed by sentinel" } },
      h("code", {},
        `${summaryLine("MUST", must, true)}\n${summaryLine("SHOULD", scan.summary.should, false)}\n${scan.findings.length} rules in ${scan.elapsedSeconds}s`,
      ),
    ),
    h("button", { class: "button button--quiet", attrs: { type: "button" }, on: { click: () => onOpen(target.key) }, text: "Inspect findings" }),
  );
}

export function renderVerdicts(data, onOpen) {
  const exits = data.meta.exitCodes;
  replaceContent(
    mount("verdicts"),
    TARGETS.map((t) => verdictColumn(t, data[t.key], exits[`${t.key}.scan`], onOpen)),
  );
}
