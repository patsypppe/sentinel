"""SHOULD rules for the result envelope.

Both rules here were graded MUST in 0.1.0 and are corrections, not additions.
The specification grades each of them SHOULD, and a harness that demands more
than the specification is producing exactly the false positive MEASUREMENTS.md
publishes as zero.
"""

from __future__ import annotations

from sentinel.catalog import checks
from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe


@rule(
    id="MCP/2026-07-28/SHOULD/server-info-echoed",
    title="Every result echoes serverInfo",
    severity=Severity.SHOULD,
    citation=f"{SPEC_BASE}/basic/index#meta",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Echo io.modelcontextprotocol/serverInfo in each result's _meta. The spec marks it "
        "Required: No, so omitting it is legal -- but clients use the (name, version) pair "
        "to attribute a logged result and to key a cache entry, and neither is possible "
        "without it."
    ),
    introduced_in="0.2.0",
)
def server_info_echoed(probe: Probe) -> RuleResult:
    return checks.server_info_echoed(probe)


@rule(
    id="MCP/2026-07-28/SHOULD/tools-list-is-deterministic",
    title="tools/list is byte-stable across repeated calls",
    severity=Severity.SHOULD,
    citation=f"{SPEC_BASE}/server/tools#capabilities",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Build the tool manifest once and serve the precomputed bytes. Any stable order "
        "satisfies this; the spec asks for determinism, not for a particular order. A "
        "manifest that reorders between calls invalidates every downstream client's cache "
        "and destroys LLM prompt-cache hit rates."
    ),
    introduced_in="0.2.0",
)
def tools_list_is_deterministic(probe: Probe) -> RuleResult:
    return checks.tools_list_deterministic(probe)
