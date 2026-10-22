"""SHOULD rules on tool names.

Both are SHOULD because the specification grades them SHOULD; a harness that
failed them as MUSTs would be demanding more than the specification does.
"""

from __future__ import annotations

import re
from collections import Counter

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe

TOOLS = f"{SPEC_BASE}/server/tools"

_ALLOWED = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")


def _names(probe: Probe) -> tuple[list[str] | None, str]:
    response = probe.tools_list()
    if not response.reached_server:
        return None, f"the server was unreachable: {response.transport_error}"
    result = response.result()
    tools = result.get("tools") if result is not None else None
    if not isinstance(tools, list):
        return None, "tools/list did not return a tools array"
    return [t["name"] for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)], ""


@rule(
    id="MCP/2026-07-28/SHOULD/tool-names-well-formed",
    title="Tool names are 1-128 characters of letters, digits, underscore, hyphen and dot",
    severity=Severity.SHOULD,
    citation=f"{TOOLS}#tool-names",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Rename tools to 1-128 characters drawn from A-Z, a-z, 0-9, underscore, hyphen "
        "and dot, with no spaces or commas. Names with other characters break the "
        "clients and gateways that put a tool name into a header, a URL or a log line."
    ),
    introduced_in="0.4.0",
)
def tool_names_well_formed(probe: Probe) -> RuleResult:
    names, why = _names(probe)
    if names is None:
        return RuleResult.indeterminate(why)
    if not names:
        return RuleResult.not_applicable("the server advertises no named tools")
    bad = [n for n in names if not _ALLOWED.match(n)]
    if bad:
        return RuleResult.failed(
            f"{len(bad)} of {len(names)} tool name(s) are not well formed: {bad[:5]}",
            evidence=repr(bad[:5]),
            key=",".join(sorted(bad)),
        )
    return RuleResult.passed(f"all {len(names)} tool name(s) are well formed")


@rule(
    id="MCP/2026-07-28/SHOULD/tool-names-unique-within-server",
    title="No two tools on one server share a name",
    severity=Severity.SHOULD,
    citation=f"{TOOLS}#tool-names",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Give every tool a distinct name. A client addresses a tool by name alone, so a "
        "duplicate makes one of the two unreachable and which one is anyone's guess."
    ),
    introduced_in="0.4.0",
)
def tool_names_unique(probe: Probe) -> RuleResult:
    names, why = _names(probe)
    if names is None:
        return RuleResult.indeterminate(why)
    if len(names) < 2:
        return RuleResult.not_applicable("fewer than two named tools")
    duplicated = sorted(n for n, count in Counter(names).items() if count > 1)
    if duplicated:
        return RuleResult.failed(
            f"duplicate tool name(s): {duplicated[:5]}",
            evidence=repr(duplicated[:5]),
            key=",".join(duplicated),
        )
    return RuleResult.passed(f"{len(names)} tool names, all distinct")
