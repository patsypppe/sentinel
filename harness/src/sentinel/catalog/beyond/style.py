"""Beyond-spec style checks."""

from __future__ import annotations

import re

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


#: Plain-string parameters whose name already says what they are. Flagging `path` on a file
#: tool, or `url` on a fetch tool, would be pedantry that costs the rule its credibility.
SELF_EVIDENT = frozenset(
    {
        "path",
        "file_path",
        "filepath",
        "url",
        "uri",
        "query",
        "id",
        "name",
        "text",
        "content",
        "command",
        "prompt",
        "message",
        "input",
        "title",
        "key",
        "value",
    }
)


#: Names every API uses the same way for paging; a description would only repeat the name.
_PAGING = frozenset(
    {
        "limit",
        "offset",
        "cursor",
        "start_cursor",
        "next_cursor",
        "page",
        "page_size",
        "pagesize",
        "per_page",
        "skip",
        "top",
        "after",
        "before",
    }
)
_FLAG_PREFIXES = ("include", "exclude", "is", "has", "enable", "allow", "only", "skip")
_UNIT_SUFFIXES = ("_ms", "_seconds", "_secs", "ms", "seconds")


def self_documenting(name: str, definition: dict[str, object]) -> bool:
    """A parameter whose name or type already says everything a description would.

    An enum lists its own values, a paging parameter means the same thing everywhere, a boolean
    called `includeHidden` says what it switches, and a number called `timeout_ms` says its unit.
    Flagging these is technically right and practically useless, so they are not flagged.
    """
    lowered = name.lower()
    kind = definition.get("type")
    if isinstance(definition.get("enum"), list) and len(definition["enum"]) >= 2:  # type: ignore[arg-type]
        return True
    if lowered in _PAGING and kind in ("integer", "number", "string"):
        return True
    if kind == "boolean" and lowered.startswith(_FLAG_PREFIXES):
        return True
    return kind in ("integer", "number") and lowered.endswith(_UNIT_SUFFIXES)


def _nested_described(definition: dict[str, object]) -> bool:
    """An object (or array of objects) whose every field carries its own description."""
    node = definition.get("items") if definition.get("type") == "array" else definition
    props = node.get("properties") if isinstance(node, dict) else None
    if not isinstance(props, dict) or not props:
        return False
    return all(
        isinstance(v, dict) and str(v.get("description") or "").strip() for v in props.values()
    )


def parameter_documented(tool: dict[str, object], name: str, definition: object) -> str | None:
    """How a parameter is documented, or None if it is not.

    "schema": the property has a `description`, or is an object whose fields all do.
    "prose": the tool's description documents it in the usual shapes (`name: ...`,
    `name (type): ...`, `name - ...` or a backticked `name`), which is where many servers put
    it, for example a docstring `Args:` block that the SDK copies into the description but not
    into the schema. A bare mention of a common word like "path" in a sentence does NOT count.
    "obvious": a parameter whose name or type says what it is (see SELF_EVIDENT and
    `self_documenting`).
    """
    if isinstance(definition, dict) and (
        str(definition.get("description") or "").strip() or _nested_described(definition)
    ):
        return "schema"
    text = str(tool.get("description") or "")
    escaped = re.escape(name)
    shaped = rf"(?<![A-Za-z0-9_])[`*]*{escaped}[`*]*\s*(?:\([^)\n]*\))?\s*[:\-\u2013\u2014]\s*\S"
    if re.search(shaped, text) or re.search(rf"[`'\"]{escaped}[`'\"]", text):
        return "prose"
    if not isinstance(definition, dict):
        return None
    plain_string = definition.get("type") == "string"
    if plain_string and name.lower() in SELF_EVIDENT and "enum" not in definition:
        return "obvious"
    if self_documenting(name, definition):
        return "obvious"
    return None


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
        if len(text) < 12 or text.lower().replace("_", " ") == name.lower().replace("_", " "):
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
        "means, its format, and an example value where the format is not obvious. A parameter "
        "documented in the tool description (`name: ...`) also counts, but the schema is the "
        "place clients and models read per-parameter meaning from."
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
            if parameter_documented(t, str(pname), pdef) is None:
                missing.append(f"{t.get('name')}.{pname}")
    if checked == 0:
        return RuleResult.not_applicable("no tool takes parameters")
    if missing:
        return RuleResult.failed(
            f"{len(missing)} of {checked} parameter(s) have no description: {missing[:6]}"
        )
    return RuleResult.passed(f"all {checked} parameters are described")
