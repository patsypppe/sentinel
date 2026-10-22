"""MUST rules on what a tool's input schema may say.

Everything here is readable from a single `tools/list` response, which makes it
cheap to check and, for the header-injection rule, worth checking. A tool whose
schema names an HTTP header gets that header written by the client from an
argument value, so a server that lets the *name* of that header contain a CR or LF
has handed a header-injection primitive to whoever controls the tool manifest.

Each rule cites the `x-mcp-header` constraint list (`#schema-extension`) or the tool
definition it restates.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from typing import Any

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe

STREAMABLE = f"{SPEC_BASE}/basic/transports/streamable-http"
TOOLS = f"{SPEC_BASE}/server/tools"

ANNOTATION = "x-mcp-header"

#: RFC 9110 §5.6.2: token = 1*tchar.
_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

#: What an `x-mcp-header` parameter may be. A header value is a flat string, so a
#: structured or floating-point value has no unambiguous encoding in one.
_HEADER_TYPES = frozenset({"string", "integer", "boolean"})


def _tools(probe: Probe) -> tuple[list[dict[str, Any]] | None, str]:
    response = probe.tools_list()
    if not response.reached_server:
        return None, f"the server was unreachable: {response.transport_error}"
    result = response.result()
    if result is None:
        return None, "tools/list did not return a result"
    tools = result.get("tools")
    if not isinstance(tools, list):
        return None, "tools/list result has no tools array"
    return [t for t in tools if isinstance(t, dict)], ""


def _annotated(tool: dict[str, Any]) -> Iterator[tuple[str, Any, dict[str, Any]]]:
    """(parameter, annotation value, parameter schema) for each annotated parameter."""
    schema = tool.get("inputSchema")
    props = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict):
        return
    for name, definition in props.items():
        if isinstance(definition, dict) and ANNOTATION in definition:
            yield str(name), definition[ANNOTATION], definition


def _scan(
    probe: Probe,
    violates: Callable[[str, str, Any, dict[str, Any]], str | None],
    what: str,
    ok: str,
) -> RuleResult:
    tools, why = _tools(probe)
    if tools is None:
        return RuleResult.indeterminate(why)
    checked = 0
    problems: list[str] = []
    keys: list[str] = []
    for tool in tools:
        tool_name = str(tool.get("name", "(unnamed)"))
        for parameter, annotation, definition in _annotated(tool):
            checked += 1
            problem = violates(tool_name, parameter, annotation, definition)
            if problem:
                problems.append(f"{tool_name}.{parameter}: {problem}")
                keys.append(f"{tool_name}.{parameter}")
    if checked == 0:
        return RuleResult.not_applicable(f"no tool declares {ANNOTATION}")
    if problems:
        return RuleResult.failed(
            f"{len(problems)} of {checked} {ANNOTATION} annotation(s) {what}: "
            + "; ".join(problems[:5]),
            evidence="; ".join(problems[:5]),
            key=",".join(sorted(keys)),
        )
    return RuleResult.passed(
        f"all {checked} {ANNOTATION} annotation(s) are {what.split(' ', 1)[-1]}"
    )


@rule(
    id="MCP/2026-07-28/MUST/x-mcp-header-not-empty",
    title="An x-mcp-header annotation names a header, not an empty string",
    severity=Severity.MUST,
    citation=f"{STREAMABLE}#schema-extension",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Give every x-mcp-header annotation a non-empty header name, or remove the "
        "annotation. An empty name asks the client to write a header with no name."
    ),
    introduced_in="0.4.0",
)
def x_mcp_header_not_empty(probe: Probe) -> RuleResult:
    def violates(_t: str, _p: str, value: Any, _d: dict[str, Any]) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return f"annotation is {value!r}"
        return None

    return _scan(probe, violates, "are empty or not a string", "name a header")


@rule(
    id="MCP/2026-07-28/MUST/x-mcp-header-token-syntax",
    title="An x-mcp-header name is a valid HTTP token",
    severity=Severity.MUST,
    citation=f"{STREAMABLE}#schema-extension",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Restrict x-mcp-header names to RFC 9110 token characters: letters, digits and "
        "!#$%&'*+-.^_`|~. A space, colon, slash or non-ASCII character cannot appear in "
        "a header name."
    ),
    introduced_in="0.4.0",
)
def x_mcp_header_token_syntax(probe: Probe) -> RuleResult:
    def violates(_t: str, _p: str, value: Any, _d: dict[str, Any]) -> str | None:
        if isinstance(value, str) and value and not _TOKEN.fullmatch(value):
            return f"{value!r} is not an RFC 9110 token"
        return None

    return _scan(probe, violates, "are not valid header tokens", "are valid header tokens")


@rule(
    id="MCP/2026-07-28/MUST/x-mcp-header-no-control-characters",
    title="An x-mcp-header name contains no control characters, including CR and LF",
    severity=Severity.MUST,
    citation=f"{STREAMABLE}#schema-extension",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Strip control characters, above all carriage return and line feed, from "
        "x-mcp-header names. A client writes this name into an HTTP request, so a CR LF "
        "in it lets whoever controls the tool manifest inject headers."
    ),
    introduced_in="0.4.0",
)
def x_mcp_header_no_control_characters(probe: Probe) -> RuleResult:
    def violates(_t: str, _p: str, value: Any, _d: dict[str, Any]) -> str | None:
        if isinstance(value, str) and any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
            return f"{value!r} contains a control character"
        return None

    return _scan(probe, violates, "contain control characters", "contain no control characters")


@rule(
    id="MCP/2026-07-28/MUST/x-mcp-header-case-insensitively-unique",
    title="x-mcp-header names are unique within a tool, ignoring case",
    severity=Severity.MUST,
    citation=f"{STREAMABLE}#schema-extension",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Give each annotated parameter of a tool a distinct header name. HTTP header "
        "names are case-insensitive, so `Region` and `region` name the same header and "
        "one argument would silently overwrite the other."
    ),
    introduced_in="0.4.0",
)
def x_mcp_header_case_insensitively_unique(probe: Probe) -> RuleResult:
    tools, why = _tools(probe)
    if tools is None:
        return RuleResult.indeterminate(why)
    checked = 0
    clashes: list[str] = []
    for tool in tools:
        seen: dict[str, str] = {}
        for parameter, value, _ in _annotated(tool):
            if not isinstance(value, str):
                continue
            checked += 1
            folded = value.lower()
            if folded in seen:
                clashes.append(f"{tool.get('name')}: {seen[folded]} and {parameter} -> {value!r}")
            else:
                seen[folded] = parameter
    if checked == 0:
        return RuleResult.not_applicable(f"no tool declares {ANNOTATION}")
    if clashes:
        return RuleResult.failed(
            f"{len(clashes)} header name clash(es): " + "; ".join(clashes[:5]),
            evidence="; ".join(clashes[:5]),
            key=",".join(sorted(clashes)),
        )
    return RuleResult.passed(f"{checked} header name(s), none equal ignoring case")


@rule(
    id="MCP/2026-07-28/MUST/x-mcp-header-primitive-types-only",
    title="An x-mcp-header parameter is a string, integer or boolean",
    severity=Severity.MUST,
    citation=f"{STREAMABLE}#schema-extension",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Only annotate parameters whose type is string, integer or boolean. A number, "
        "object or array has no single unambiguous encoding in a header value."
    ),
    introduced_in="0.4.0",
)
def x_mcp_header_primitive_types_only(probe: Probe) -> RuleResult:
    def violates(_t: str, _p: str, _v: Any, definition: dict[str, Any]) -> str | None:
        declared = definition.get("type")
        # No type, or a type array such as ["string", "null"], is not shown to be
        # outside the permitted set, so only a declared non-primitive is a violation.
        if isinstance(declared, str) and declared not in _HEADER_TYPES:
            return f"type is {declared!r}"
        return None

    return _scan(
        probe,
        violates,
        "are on a parameter that is not a string, integer or boolean",
        "sit on a string, integer or boolean parameter",
    )


@rule(
    id="MCP/2026-07-28/MUST/tools-declare-valid-input-schema",
    title="A tool's inputSchema, when present, is a JSON Schema object and not null",
    severity=Severity.MUST,
    citation=f"{TOOLS}#tool",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        'Make inputSchema a JSON Schema object with type "object". Use '
        '{"type": "object"} for a tool with no arguments; null, a string or an array '
        "is not a schema."
    ),
    introduced_in="0.4.0",
)
def tools_declare_valid_input_schema(probe: Probe) -> RuleResult:
    tools, why = _tools(probe)
    if tools is None:
        return RuleResult.indeterminate(why)
    # A tool that omits inputSchema entirely is `tools-declare-input-schema`'s
    # finding. Reporting it here too would count one defect twice.
    declared = [t for t in tools if "inputSchema" in t]
    if not declared:
        return RuleResult.not_applicable("no tool declares an inputSchema to validate")
    bad: list[str] = []
    for tool in declared:
        schema = tool["inputSchema"]
        name = str(tool.get("name", "(unnamed)"))
        if not isinstance(schema, dict):
            bad.append(f"{name}: inputSchema is {type(schema).__name__}")
        elif schema.get("type", "object") != "object":
            bad.append(f"{name}: type is {schema.get('type')!r}, not 'object'")
    if bad:
        return RuleResult.failed(
            f"{len(bad)} of {len(declared)} inputSchema(s) are not valid: " + "; ".join(bad[:5]),
            evidence="; ".join(bad[:5]),
            key=",".join(sorted(bad)),
        )
    return RuleResult.passed(f"all {len(declared)} declared inputSchema(s) are objects")
