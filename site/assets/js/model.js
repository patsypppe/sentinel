/** Shared vocabulary for outcomes, severities and targets. */

export const OUTCOMES = [
  { key: "fail", label: "Fail" },
  { key: "indeterminate", label: "Indeterminate" },
  { key: "pass", label: "Pass" },
  { key: "not_applicable", label: "N/A" },
];

export const OUTCOME_RANK = Object.fromEntries(OUTCOMES.map((o, i) => [o.key, i]));
export const outcomeLabel = (key) => OUTCOMES.find((o) => o.key === key)?.label ?? key;

export const TARGETS = [
  {
    key: "nonconformant",
    label: "Unmigrated server",
    role: "Non-conformant fixture that still speaks the old, stateful protocol. It must fail.",
  },
  {
    key: "broker",
    label: "Broker",
    role: "The Go server, scanned through its authenticated path with a minted token.",
  },
  {
    key: "conformant",
    label: "Conformant fixture",
    role: "A minimal correct server. Any FAIL here would be a false positive.",
  },
];

const SEVERITY_ORDER = { must: 0, should: 1, may: 2 };

export function sortFindings(findings) {
  return [...findings].sort(
    (a, b) =>
      OUTCOME_RANK[a.outcome] - OUTCOME_RANK[b.outcome] ||
      (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) ||
      a.ruleId.localeCompare(b.ruleId),
  );
}

/** "MCP/2026-07-28/MUST/x-y" -> { prefix: "MCP/2026-07-28/MUST/", slug: "x-y" } */
export function splitRuleId(id) {
  const cut = id.lastIndexOf("/");
  return cut < 0 ? { prefix: "", slug: id } : { prefix: id.slice(0, cut + 1), slug: id.slice(cut + 1) };
}

export function shortRuleId(id) {
  return id.replace(/^MCP\/\d{4}-\d{2}-\d{2}\//, "");
}

export function formatDate(iso) {
  const d = new Date(`${iso}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
}
