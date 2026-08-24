"""SHOULD rules for error-code allocation.

The 2026-07-28 revision partitions the JSON-RPC server-error range and retires
the sub-range implementations used to allocate from:

    "-32000 to -32019 -- legacy. Codes in this sub-range were allocated by
    implementations before this policy was introduced. New codes MUST NOT be
    allocated in this sub-range, and new implementations SHOULD NOT use codes
    from this sub-range at all. Apart from -32002, receivers MUST NOT assume any
    specific meaning for these codes."

Graded SHOULD, not MUST, and the distinction is the spec's own. "MUST NOT be
allocated" binds whoever mints a *new* code; what a running server *emits* is
graded "SHOULD NOT use ... at all". A harness cannot see when a code was
allocated, only what comes back on the wire, so the verifiable half is the
SHOULD -- and grading it MUST would fail every unmigrated server for a
requirement the specification did not make of it.
"""

from __future__ import annotations

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe
from sentinel.probe.transport import RawResponse

#: The sub-range this revision retired, inclusive.
LEGACY_LOW, LEGACY_HIGH = -32019, -32000

#: -32002 is excluded deliberately. It is in the legacy sub-range, but a server
#: emitting it for resource-not-found is already caught by
#: MCP/2026-07-28/MUST/resource-not-found-is-invalid-params, and reporting one
#: defect twice makes a report harder to act on, not more thorough. It is also
#: the one code the revision exempts by name -- "apart from -32002" -- so a
#: receiver may still assume a meaning for it.
_EXCLUDED = {-32002}


@rule(
    id="MCP/2026-07-28/SHOULD/no-errors-in-legacy-range",
    title="No error code comes from the retired -32000…-32019 sub-range",
    severity=Severity.SHOULD,
    citation=f"{SPEC_BASE}/basic/index#error-codes",
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Move implementation-defined codes outside the JSON-RPC reserved range "
        "(-32768 to -32000) entirely. The revision retired -32000…-32019: 'new "
        "implementations SHOULD NOT use codes from this sub-range at all', and apart "
        "from -32002 'receivers MUST NOT assume any specific meaning for these codes' "
        "-- so a code you emit there is a code no client can interpret."
    ),
    introduced_in="0.2.0",
)
def no_errors_in_legacy_range(probe: Probe) -> RuleResult:
    provocations: list[tuple[str, RawResponse]] = [
        ("an unknown method", probe.call("sentinel/definitely-not-a-real-method")),
        ("an unknown tool", probe.tools_call("sentinel-no-such-tool", {})),
        ("an unknown resource", probe.resources_read("sentinel://no/such/resource")),
        ("tools/call with no name", probe.call("tools/call", {})),
        ("a missing Mcp-Method header", probe.tools_list(omit_mcp_method=True)),
    ]

    offenders: list[str] = []
    observed = 0
    for label, response in provocations:
        error = response.error()
        if not isinstance(error, dict):
            continue
        code = error.get("code")
        if not isinstance(code, int):
            continue
        observed += 1
        if code in _EXCLUDED:
            continue
        if LEGACY_LOW <= code <= LEGACY_HIGH:
            offenders.append(f"{label} returned {code}")

    if observed == 0:
        return RuleResult.indeterminate("no provocation produced an error to inspect")
    if offenders:
        return RuleResult.failed(
            f"{len(offenders)} of {observed} errors came from the retired "
            f"-32000…-32019 sub-range: {offenders}",
            evidence="; ".join(offenders),
        )
    return RuleResult.passed(
        f"none of {observed} provoked errors used the retired sub-range"
    )
