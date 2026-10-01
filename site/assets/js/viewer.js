/** §2: the interactive report viewer. State lives in the URL so a view is shareable. */
import { h, append, replaceContent, safeHref } from "./dom.js";
import { OUTCOMES, TARGETS, outcomeLabel, sortFindings, splitRuleId } from "./model.js";

const FACETS = {
  outcome: [{ key: "all", label: "All" }, ...OUTCOMES],
  severity: [{ key: "all", label: "All" }, { key: "must", label: "MUST" }, { key: "should", label: "SHOULD" }],
  namespace: [{ key: "all", label: "All" }, { key: "MCP", label: "MCP spec" }, { key: "SENTINEL", label: "Beyond spec" }],
};
const DEFAULTS = { target: "nonconformant", outcome: "all", severity: "all", namespace: "all", q: "" };
const PARAM = { target: "target", outcome: "outcome", severity: "severity", namespace: "ns", q: "q" };

function readState() {
  const params = new URLSearchParams(window.location.search);
  const state = { ...DEFAULTS };
  for (const [key, name] of Object.entries(PARAM)) {
    const value = params.get(name);
    if (value === null) continue;
    if (key === "q") state.q = value.slice(0, 120);
    else if (key === "target" && TARGETS.some((t) => t.key === value)) state.target = value;
    else if (FACETS[key]?.some((f) => f.key === value)) state[key] = value;
  }
  return state;
}

function writeState(state) {
  const params = new URLSearchParams(window.location.search);
  for (const [key, name] of Object.entries(PARAM)) {
    if (state[key] === DEFAULTS[key]) params.delete(name);
    else params.set(name, state[key]);
  }
  const query = params.toString();
  history.replaceState(null, "", `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`);
}

function matches(finding, state, ignore) {
  if (ignore !== "outcome" && state.outcome !== "all" && finding.outcome !== state.outcome) return false;
  if (state.severity !== "all" && finding.severity !== state.severity) return false;
  if (state.namespace !== "all" && finding.namespace !== state.namespace) return false;
  if (state.q) {
    const hay = `${finding.ruleId} ${finding.title} ${finding.detail} ${finding.evidence} ${finding.remediation}`.toLowerCase();
    if (!hay.includes(state.q.toLowerCase())) return false;
  }
  return true;
}

function radio(name, option, checked, extra) {
  const id = `f-${name}-${option.key}`;
  return h("span", { class: "chip" },
    h("input", { attrs: { type: "radio", name, id, value: option.key, checked } }),
    h("label", { attrs: { for: id }, dataset: { outcome: option.key } }, option.label, extra),
  );
}

function citation(finding) {
  const href = finding.citation ? safeHref(finding.citation) : null;
  if (!href) {
    return h("span", { class: "muted", text: "Beyond spec: carries a rationale instead of a citation, and can never fail a spec gate." });
  }
  const shown = href.replace(/^https:\/\/modelcontextprotocol\.io\/specification\//, "spec/");
  return h("a", { attrs: { href, rel: "noopener" }, text: shown });
}

function findingRow(f) {
  const { prefix, slug } = splitRuleId(f.ruleId);
  const rows = [
    ["Observed", h("span", { text: f.detail })],
    f.evidence && f.evidence !== f.detail ? ["Evidence", h("code", { class: "evidence", text: f.evidence })] : null,
    ["Remediation", h("span", { text: f.remediation })],
    ["Spec clause", citation(f)],
    ["Verifiability", h("span", { class: "mono", text: f.verifiability.replace("_", "-") })],
    ["Elapsed", h("span", { class: "mono", text: `${(f.elapsedSeconds * 1000).toFixed(1)} ms` })],
  ].filter(Boolean);

  return h("li", { class: `finding finding--${f.outcome}` },
    h("details", {},
      h("summary", {},
        h("span", { class: `tag tag--${f.outcome}`, text: outcomeLabel(f.outcome) }),
        h("span", { class: "finding__id" },
          h("span", { class: "finding__prefix", text: prefix }),
          h("span", { class: "finding__slug", text: slug }),
        ),
        h("span", { class: "finding__title", text: f.title }),
      ),
      h("dl", { class: "finding__body" },
        rows.map(([term, value]) => h("div", {}, h("dt", { text: term }), h("dd", {}, value))),
      ),
    ),
  );
}

export function createViewer(data) {
  const root = document.querySelector('[data-mount="viewer"]');
  const ref = (name) => root.querySelector(`[data-ref="${name}"]`);
  const state = readState();

  append(ref("targets"), TARGETS.map((t) => radio("target", t, state.target === t.key)));
  const facetMounts = { outcome: ref("outcomes"), severity: ref("severities"), namespace: ref("namespaces") };
  const counters = {};
  for (const [facet, el] of Object.entries(facetMounts)) {
    for (const option of FACETS[facet]) {
      const counter = facet === "outcome" ? h("span", { class: "chip__count" }) : null;
      if (counter) counters[option.key] = counter;
      append(el, [radio(facet, option, state[facet] === option.key, counter)]);
    }
  }
  const search = ref("search");
  search.value = state.q;

  function render() {
    const scan = data[state.target];
    const base = scan.findings.filter((f) => matches(f, state, "outcome"));
    for (const option of FACETS.outcome) {
      const n = option.key === "all" ? base.length : base.filter((f) => f.outcome === option.key).length;
      counters[option.key].textContent = String(n);
    }
    const shown = sortFindings(base.filter((f) => matches(f, state)));
    replaceContent(ref("list"), shown.map(findingRow));
    ref("empty").hidden = shown.length > 0;
    const target = TARGETS.find((t) => t.key === state.target);
    ref("count").textContent = `${shown.length} of ${scan.findings.length} findings · ${target.label}`;
    ref("summary").textContent = `endpoint ${scan.endpoint} · spec ${scan.specRevision} · ${scan.elapsedSeconds}s`;
    writeState(state);
  }

  const form = ref("controls");
  form.addEventListener("change", (event) => {
    const { name, value } = event.target;
    if (name in state && name !== "q") {
      state[name] = value;
      render();
    }
  });
  search.addEventListener("input", () => {
    state.q = search.value.trim().slice(0, 120);
    render();
  });
  form.addEventListener("submit", (event) => event.preventDefault());

  render();

  return {
    show(targetKey) {
      state.target = targetKey;
      const input = form.querySelector(`input[name="target"][value="${targetKey}"]`);
      if (input) input.checked = true;
      render();
      document.getElementById("report").scrollIntoView();
      input?.focus({ preventScroll: true });
    },
  };
}
