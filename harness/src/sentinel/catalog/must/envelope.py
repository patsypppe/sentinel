"""MUST rules for the request/result envelope (`SN-CAP-02`, `SN-CAP-11`)."""

from __future__ import annotations

from collections.abc import Callable

from sentinel.catalog import checks
from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe
from sentinel.probe.transport import RawResponse

BASIC = f"{SPEC_BASE}/basic"
CHANGELOG = f"{SPEC_BASE}/changelog"

#: The list and read endpoints CacheableResult applies to.
LIST_ENDPOINTS: list[tuple[str, Callable[[Probe], RawResponse]]] = [
    ("server/discover", lambda p: p.discover()),
    ("tools/list", lambda p: p.tools_list()),
    ("resources/list", lambda p: p.resources_list()),
    ("resources/templates/list", lambda p: p.resource_templates_list()),
    ("prompts/list", lambda p: p.prompts_list()),
]


@rule(
    id="MCP/2026-07-28/MUST/result-type-present",
    title="Every result carries a non-empty resultType",
    severity=Severity.MUST,
    citation=f"{BASIC}/index#result-envelope",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Set resultType on every result — 'complete', or 'input_required' when the call "
        "needs another round trip. Without it a client cannot tell a finished answer from "
        "one that is waiting on the user, and will treat a half-finished call as done."
    ),
)
def result_type_present(probe: Probe) -> RuleResult:
    missing: list[str] = []
    checked = 0

    for name, send in LIST_ENDPOINTS:
        result = send(probe).result()
        if result is None:
            continue
        checked += 1
        if not result.get("resultType"):
            missing.append(name)

    if checked == 0:
        return RuleResult.indeterminate("no endpoint returned a result to inspect")
    if missing:
        return RuleResult.failed(
            f"{len(missing)} of {checked} results omit resultType: {missing}",
            evidence=f"endpoints missing resultType: {missing}",
        )
    return RuleResult.passed(f"all {checked} results carry resultType")


@rule(
    id="MCP/2026-07-28/MUST/server-info-echoed",
    title="Every result echoes serverInfo",
    severity=Severity.MUST,
    citation=f"{BASIC}/index#result-envelope",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Echo io.modelcontextprotocol/serverInfo in each result's _meta. Clients key cache "
        "entries on the (name, version) pair, so a result that omits it cannot be cached "
        "and cannot be attributed if it is logged."
    ),
    deprecated_in="0.2.0",
    superseded_by="MCP/2026-07-28/SHOULD/server-info-echoed",
)
def server_info_echoed_deprecated(probe: Probe) -> RuleResult:
    # Graded MUST in 0.1.0. The specification marks serverInfo "Required: No"
    # under "Servers SHOULD include the following field in every result's
    # _meta", so this demanded more than the spec does -- exactly the false
    # positive MEASUREMENTS.md publishes as zero. Superseded, not edited,
    # because ids are permanent.
    return checks.server_info_echoed(probe)


@rule(
    id="MCP/2026-07-28/MUST/cacheable-results-carry-ttl",
    title="Every list and read result carries ttlMs",
    severity=Severity.MUST,
    citation=f"{CHANGELOG}#cacheableresult-is-required",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Add ttlMs to every list and read result. CacheableResult became required in this "
        "revision; without a TTL a client must either re-fetch the manifest on every turn "
        "or cache it for a duration it invented."
    ),
)
def cacheable_ttl(probe: Probe) -> RuleResult:
    missing: list[str] = []
    checked = 0

    for name, send in LIST_ENDPOINTS:
        result = send(probe).result()
        if result is None:
            continue
        checked += 1
        if not isinstance(result.get("ttlMs"), int):
            missing.append(name)

    if checked == 0:
        return RuleResult.indeterminate("no list endpoint returned a result")
    if missing:
        return RuleResult.failed(
            f"{len(missing)} of {checked} list results omit ttlMs: {missing}",
            evidence=f"endpoints missing ttlMs: {missing}",
        )
    return RuleResult.passed(f"all {checked} list results carry ttlMs")


@rule(
    id="MCP/2026-07-28/MUST/cacheable-results-carry-scope",
    title="Every list and read result carries cacheScope",
    severity=Severity.MUST,
    citation=f"{CHANGELOG}#cacheableresult-is-required",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Add cacheScope ('private' or 'public') to every list and read result. Choose it "
        "deliberately: 'public' on a response that varies by the caller's scopes lets a "
        "shared intermediary serve one tenant's data to another."
    ),
)
def cacheable_scope(probe: Probe) -> RuleResult:
    missing: list[str] = []
    invalid: list[str] = []
    checked = 0

    for name, send in LIST_ENDPOINTS:
        result = send(probe).result()
        if result is None:
            continue
        checked += 1
        scope = result.get("cacheScope")
        if scope is None:
            missing.append(name)
        elif scope not in ("private", "public"):
            invalid.append(f"{name}={scope!r}")

    if checked == 0:
        return RuleResult.indeterminate("no list endpoint returned a result")
    if missing or invalid:
        parts = []
        if missing:
            parts.append(f"missing cacheScope: {missing}")
        if invalid:
            parts.append(f"invalid cacheScope: {invalid}")
        return RuleResult.failed("; ".join(parts), evidence="; ".join(parts))
    return RuleResult.passed(f"all {checked} list results carry a valid cacheScope")


@rule(
    id="MCP/2026-07-28/MUST/tools-list-is-deterministic",
    title="tools/list is byte-stable across repeated calls",
    severity=Severity.MUST,
    citation=f"{CHANGELOG}#deterministic-tool-ordering",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Build the tool manifest once, sort it by name byte-wise, and serve the "
        "precomputed bytes. A manifest that reorders between calls invalidates every "
        "downstream client's cache and destroys LLM prompt-cache hit rates."
    ),
    deprecated_in="0.2.0",
    superseded_by="MCP/2026-07-28/SHOULD/tools-list-is-deterministic",
)
def tools_list_deterministic_deprecated(probe: Probe) -> RuleResult:
    # Graded MUST in 0.1.0. "Servers SHOULD return tools in a deterministic
    # order" is a SHOULD. The MUST in the same paragraph is a different
    # property -- "MUST NOT vary per-connection" -- which this never tested,
    # because all twenty calls shared one connection. See
    # MCP/2026-07-28/MUST/tools-list-connection-independent.
    return checks.tools_list_deterministic(probe)


@rule(
    id="MCP/2026-07-28/MUST/tools-declare-input-schema",
    title="Every advertised tool declares an input schema",
    severity=Severity.MUST,
    citation=f"{BASIC}/index#tools",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Give every tool an inputSchema. A model calling a tool with no schema has to "
        "guess the argument shape from the description, and will guess wrong."
    ),
)
def tools_declare_schema(probe: Probe) -> RuleResult:
    result = probe.tools_list().result()
    if result is None:
        return RuleResult.not_applicable("tools/list did not return a result")

    tools = result.get("tools")
    if not isinstance(tools, list):
        return RuleResult.failed(f"tools is not an array: {tools!r}")
    if not tools:
        return RuleResult.not_applicable("this server advertises no tools")

    bad = [
        t.get("name", "<unnamed>")
        for t in tools
        if not isinstance(t, dict) or not isinstance(t.get("inputSchema"), dict)
    ]
    if bad:
        return RuleResult.failed(
            f"{len(bad)} of {len(tools)} tools declare no input schema: {bad}",
            evidence=f"tools without inputSchema: {bad}",
        )
    return RuleResult.passed(f"all {len(tools)} tools declare an input schema")


@rule(
    id="MCP/2026-07-28/MUST/tools-are-named",
    title="Every advertised tool has a name",
    severity=Severity.MUST,
    citation=f"{BASIC}/index#tools",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Give every tool a non-empty name. It is the only handle a client has for calling "
        "it, and it is what Mcp-Name must carry on a tools/call."
    ),
)
def tools_are_named(probe: Probe) -> RuleResult:
    result = probe.tools_list().result()
    if result is None:
        return RuleResult.not_applicable("tools/list did not return a result")

    tools = result.get("tools")
    if not isinstance(tools, list):
        return RuleResult.failed(f"tools is not an array: {tools!r}")
    if not tools:
        return RuleResult.not_applicable("this server advertises no tools")

    unnamed = sum(1 for t in tools if not isinstance(t, dict) or not t.get("name"))
    if unnamed:
        return RuleResult.failed(f"{unnamed} of {len(tools)} tools have no name")
    return RuleResult.passed(f"all {len(tools)} tools are named")
