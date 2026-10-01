/** §3: the five unverifiable MUSTs, with the harness's own explanation of each. */
import { h, mount, replaceContent, safeHref } from "./dom.js";
import { TARGETS, splitRuleId } from "./model.js";

export function renderIndeterminate(data) {
  const reference = data.nonconformant;
  const byId = new Map(reference.findings.map((f) => [f.ruleId, f]));
  const items = reference.unverifiable.map((u) => {
    const finding = byId.get(u.ruleId);
    const seenOn = TARGETS.filter((t) => data[t.key].unverifiable.some((x) => x.ruleId === u.ruleId));
    const href = finding && safeHref(finding.citation);
    return h("li", { class: "indet__item" },
      h("h3", { class: "indet__rule" },
        h("span", { class: "tag tag--indeterminate", text: "Indeterminate" }),
        h("span", { class: "mono", text: splitRuleId(u.ruleId).slug }),
      ),
      finding ? h("p", { class: "indet__title", text: finding.title }) : null,
      h("p", { class: "indet__why", text: u.why }),
      h("p", { class: "indet__foot" },
        `Reported on ${seenOn.length} of ${TARGETS.length} scans · excluded from the gate`,
        href ? [" · ", h("a", { attrs: { href, rel: "noopener" }, text: "spec clause" })] : null,
      ),
    );
  });
  replaceContent(mount("indeterminate"), items);
}
