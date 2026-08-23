"""MUST rules that cannot be settled from the wire.

`docs/HANDOFF.md` §8.8:

    "INDETERMINATE is not optional and not a weakness. Several MUSTs — 'MUST NOT
    accept a token not issued for this server', 'MUST NOT treat handle
    possession as authentication' — cannot be proven black-box against an
    arbitrary server. A harness that silently scores them as passes is lying.
    Report them in their own bucket, exclude them from the gate, and list them
    in the README under limitations. Saying so is the credibility move;
    papering over it is the thing a reviewer will catch."

Every rule here returns INDETERMINATE, and `BaseRule.evaluate` coerces anything
else to INDETERMINATE if a future edit tries to make one of them pass. Each says
precisely WHY it cannot be settled and what WOULD settle it, so the limitation
is actionable rather than a shrug.
"""

from __future__ import annotations

from sentinel.catalog.base import SPEC_BASE, RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe

SECURITY = f"{SPEC_BASE}/basic/security_best_practices"


@rule(
    id="MCP/2026-07-28/MUST/token-audience-validated",
    title="The server rejects tokens not issued for it",
    severity=Severity.MUST,
    citation=f"{SECURITY}#token-audience-binding",
    verifiability=Verifiability.UNVERIFIABLE,
    remediation=(
        "Check that the token's `aud` claim contains this server's identifier, by exact "
        "string equality — not a prefix or substring match. Reject anything else. This is "
        "the specification's explicit MUST NOT, and a server that skips it is a confused "
        "deputy for every other service sharing its issuer."
    ),
)
def token_audience_validated(_: Probe) -> RuleResult:
    return RuleResult.indeterminate(
        "Settling this needs a token that is correctly signed by the server's OWN issuer "
        "but carries a different audience. The harness cannot mint one — it does not hold "
        "the issuer's signing key — and a token it can forge would be rejected for its "
        "signature, which proves nothing about the audience check. "
        "To settle it: mint such a token with your issuer and confirm the server refuses "
        "it, or read the one place the server accepts a token."
    )


@rule(
    id="MCP/2026-07-28/MUST/no-token-passthrough",
    title="The server does not forward inbound tokens downstream",
    severity=Severity.MUST,
    citation=f"{SECURITY}#token-passthrough",
    verifiability=Verifiability.UNVERIFIABLE,
    remediation=(
        "Use the server's own credential for downstream calls and never the caller's "
        "token. The structural version of this is to keep the inbound token out of "
        "whatever type represents the authenticated principal, so there is nothing to "
        "forward even by accident."
    ),
)
def no_token_passthrough(_: Probe) -> RuleResult:
    return RuleResult.indeterminate(
        "What a server sends to its own dependencies is invisible from the client side. "
        "No sequence of requests can distinguish a server that forwards the caller's token "
        "from one that presents its own. "
        "To settle it: capture the server's egress traffic while it serves an "
        "authenticated call and confirm the inbound token appears in none of it."
    )


@rule(
    id="MCP/2026-07-28/MUST/handle-possession-is-not-authentication",
    title="Server-minted handles are re-verified against the caller",
    severity=Severity.MUST,
    citation=f"{SECURITY}#state-handles",
    verifiability=Verifiability.UNVERIFIABLE,
    remediation=(
        "Re-verify the principal and tenant on EVERY handle resolution, against the "
        "validated token rather than against the handle. Return one indistinguishable "
        "error for 'does not exist' and 'not yours', or the handle space becomes an "
        "enumeration oracle."
    ),
)
def handle_possession_not_auth(_: Probe) -> RuleResult:
    return RuleResult.indeterminate(
        "Settling this needs TWO authenticated principals on the same server: mint a handle "
        "as one, present it as the other, and confirm the refusal. A single-credential scan "
        "cannot construct the second half. "
        "To settle it: run the scan with two principals' credentials, or read the one place "
        "the server resolves a handle."
    )


@rule(
    id="MCP/2026-07-28/MUST/mrtr-retries-are-idempotent",
    title="A duplicate MRTR retry performs no additional side effect",
    severity=Severity.MUST,
    citation=f"{SPEC_BASE}/basic/patterns/mrtr#idempotency",
    verifiability=Verifiability.UNVERIFIABLE,
    remediation=(
        "Record the result when a flow is consumed and replay it verbatim on any duplicate "
        "retry, performing zero further effects. Commit the effect and the record in one "
        "transaction, so a crash between them cannot re-execute on the next retry."
    ),
)
def mrtr_idempotent(_: Probe) -> RuleResult:
    return RuleResult.indeterminate(
        "A duplicate retry that returns the right answer is indistinguishable from the wire "
        "from one that performed the side effect a second time and returned the right "
        "answer again — which is exactly the failure this rule is about. Confirming it "
        "requires observing the effect, not the response. "
        "To settle it: retry a completed flow and count the effect at its source — a row "
        "count, a downstream call log — rather than reading the reply."
    )


@rule(
    id="MCP/2026-07-28/MUST/invocations-are-audited",
    title="Every tool invocation is recorded in an append-only log",
    severity=Severity.MUST,
    citation=f"{SECURITY}#audit-logging",
    verifiability=Verifiability.UNVERIFIABLE,
    remediation=(
        "Write an append-only, hash-chained row for every invocation, and fail the "
        "invocation if the write fails. Enforce append-only with database grants rather "
        "than convention, so the property does not depend on every future code path "
        "remembering it."
    ),
)
def invocations_audited(_: Probe) -> RuleResult:
    return RuleResult.indeterminate(
        "An audit log is not exposed over MCP, and a server that claimed to keep one would "
        "be believed on its own word — which is the opposite of what an audit is for. "
        "To settle it: read the log directly and verify its chain, e.g. with a "
        "verification command the server ships."
    )
