/** §4.1: `sentinel migrate` output for the unmigrated server. */
import { h, mount, replaceContent } from "./dom.js";
import { shortRuleId } from "./model.js";

const DOCS = "https://github.com/patsypppe/sentinel/blob/main/docs/MIGRATION.md";

function change(c) {
  const state = c.outstanding ? "outstanding" : c.confidence === "unknown" ? "unknown" : "done";
  const stateLabel = { outstanding: "Outstanding", unknown: "Not checkable", done: "Done" }[state];
  const stateTag = { outstanding: "fail", unknown: "indeterminate", done: "pass" }[state];
  return h("li", { class: `change change--${state}` },
    h("p", { class: "change__tags" },
      h("span", { class: `tag tag--${stateTag}`, text: stateLabel }),
      h("span", { class: "tag tag--plain", text: c.impact }),
      h("span", { class: "change__hours", text: `~${c.effort_hours} h` }),
    ),
    h("h3", { class: "change__title" },
      c.doc_section ? h("a", { attrs: { href: `${DOCS}#${encodeURIComponent(c.doc_section)}` }, text: c.title }) : c.title,
    ),
    c.failing_rules.length
      ? h("p", { class: "change__rules" }, h("span", { class: "muted", text: "seen by " }), c.failing_rules.map(shortRuleId).join(", "))
      : h("p", { class: "change__rules muted", text: "no wire evidence either way; check by hand" }),
  );
}

export function renderMigration(data) {
  const m = data.migrate;
  replaceContent(mount("migration"),
    h("dl", { class: "mig__figures" },
      h("div", {}, h("dt", { text: "breaking changes outstanding" }), h("dd", { text: `${m.outstanding_count} of ${m.breaking_changes}` })),
      h("div", {}, h("dt", { text: "estimated effort, outstanding" }), h("dd", { text: `~${m.outstanding_effort_hours} h` })),
      h("div", {}, h("dt", { text: "not checkable from the wire" }), h("dd", { text: m.undetectable_count })),
    ),
    h("ol", { class: "changes" }, m.changes.map(change)),
    h("p", { class: "cite", text: "Source: data/nonconformant.migrate.json. sentinel migrate describes work, not a verdict, and never fails a gate." }),
  );
}
