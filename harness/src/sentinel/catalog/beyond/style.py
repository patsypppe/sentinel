"""Beyond-spec style checks."""

from __future__ import annotations

from sentinel.catalog import checks
from sentinel.catalog.base import RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe


@rule(
    id="SENTINEL/STYLE/tools-sorted-by-name",
    title="tools/list returns tools in byte-wise name order",
    severity=Severity.SHOULD,
    rationale=(
        "The specification asks for a deterministic order and says nothing about which "
        "order. A stable but unsorted manifest conforms fully. Byte-wise name order is "
        "worth having anyway: it means two deployments advertising the same tools produce "
        "the same manifest bytes, which is what makes a manifest hash comparable across "
        "environments -- and comparable hashes are what drift detection runs on."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation=("Sort tools by name byte-wise (not case-insensitively, not by locale collation)."),
    introduced_in="0.2.0",
)
def tools_sorted_by_name(probe: Probe) -> RuleResult:
    return checks.tools_sorted_by_name(probe)


@rule(
    id="SENTINEL/STYLE/tools-have-descriptions",
    title="Every tool has a description",
    severity=Severity.SHOULD,
    rationale=(
        "`description` is optional in the specification's Tool schema, so a tool without one "
        "conforms. It is what a model reads to choose between tools, though, so an "
        "undescribed tool is either never selected or selected by accident."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation="Describe every tool in a sentence a model could choose it by.",
    introduced_in="0.4.0",
)
def tools_have_descriptions(probe: Probe) -> RuleResult:
    from sentinel.catalog.should.ordering import tools_described

    return tools_described.check(probe)


def _tools(probe: Probe) -> list[dict[str, object]] | None:
    result = probe.tools_list().result()
    tools = (result or {}).get("tools")
    if not isinstance(tools, list):
        return None
    return [t for t in tools if isinstance(t, dict)]


@rule(
    id="SENTINEL/STYLE/description-states-purpose",
    title="Every tool description says what the tool does",
    severity=Severity.SHOULD,
    rationale=(
        "A 2026 study of 856 tools in 103 MCP servers (arXiv 2602.14878) found that 56% of "
        "descriptions fail to state their purpose clearly. The description is all a model has "
        "to choose a tool, so a stub such as the tool's own name is an unusable description. "
        "This check is deliberately crude (too short, or just the name): it flags the clear "
        "cases and says nothing about borderline ones."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Write a sentence that says what the tool does and when to use it, for example "
        "'Search open issues by keyword and return the 10 most recent matches.'"
    ),
    introduced_in="0.4.0",
)
def description_states_purpose(probe: Probe) -> RuleResult:
    tools = _tools(probe)
    if not tools:
        return RuleResult.not_applicable("this server advertises no tools")
    weak = []
    for t in tools:
        name = str(t.get("name", ""))
        text = str(t.get("description") or "").strip()
        if len(text) < 20 or text.lower().replace("_", " ") == name.lower().replace("_", " "):
            weak.append(name)
    if weak:
        return RuleResult.failed(f"{len(weak)} tool(s) have a stub description: {weak[:5]}")
    return RuleResult.passed(f"all {len(tools)} tool descriptions are more than a stub")


@rule(
    id="SENTINEL/STYLE/parameters-are-described",
    title="Every tool parameter has a description",
    severity=Severity.SHOULD,
    rationale=(
        "A 2026 study of 10,831 MCP servers (arXiv 2602.18914) found thousands of tools with "
        "missing or incorrect parameter semantics, and showed in a mutation experiment that "
        "such smells measurably change which tool an LLM selects. A parameter named `q` or "
        "`id` is a guess unless it is described."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Add a `description` to every property in the tool's inputSchema, saying what it "
        "means, its format, and an example value where the format is not obvious."
    ),
    introduced_in="0.4.0",
)
def parameters_are_described(probe: Probe) -> RuleResult:
    tools = _tools(probe)
    if not tools:
        return RuleResult.not_applicable("this server advertises no tools")
    missing: list[str] = []
    checked = 0
    for t in tools:
        schema = t.get("inputSchema")
        props = schema.get("properties") if isinstance(schema, dict) else None
        if not isinstance(props, dict):
            continue
        for pname, pdef in props.items():
            checked += 1
            if not (isinstance(pdef, dict) and str(pdef.get("description") or "").strip()):
                missing.append(f"{t.get('name')}.{pname}")
    if checked == 0:
        return RuleResult.not_applicable("no tool takes parameters")
    if missing:
        return RuleResult.failed(
            f"{len(missing)} of {checked} parameter(s) have no description: {missing[:6]}"
        )
    return RuleResult.passed(f"all {checked} parameters are described")
