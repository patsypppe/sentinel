"""Beyond-spec operational checks on what a manifest costs to mount.

These are `SENTINEL/OPS/*`: the specification says nothing about manifest size,
so a server that fails one of these is not non-conformant. It is expensive.
`--gate must` never considers them; `--gate ops` does, and only them.
"""

from __future__ import annotations

from sentinel.budget import BudgetPolicy, manifest_cost, tolerance_note
from sentinel.catalog.base import RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe

#: Two descriptions closer than this are treated as the same text for the
#: duplicate check. Exact equality only: a similarity threshold would be a
#: judgement this rule has no way to defend.
_DUPLICATE_MIN_LENGTH = 40


def _policy(probe: Probe) -> BudgetPolicy:
    return getattr(probe, "budgets", BudgetPolicy())


def _tools(probe: Probe) -> list[object] | None:
    result = probe.tools_list().result()
    if result is None:
        return None
    tools = result.get("tools")
    return tools if isinstance(tools, list) else None


@rule(
    id="SENTINEL/OPS/manifest-token-budget",
    title="the whole tool manifest fits the operator's token budget",
    severity=Severity.MUST,
    rationale=(
        "An agent pays for every tool description in every mounted manifest, on every "
        "initialization, before it reads the user's first message. Nothing in the "
        "specification bounds that, so a fully conformant server can still consume a "
        "large share of a context window on its own. This makes the cost visible and "
        "gateable. The budget is supplied by the operator because the right ceiling "
        "depends on the model, the number of servers mounted, and how much of the "
        "window the team will spend before the conversation starts -- none of which "
        "are knowable from the wire."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Reduce the manifest: consolidate overlapping tools, move long prose out of "
        "descriptions, and replace inlined enums with a bounded reference."
    ),
    introduced_in="0.3.0",
)
def manifest_token_budget(probe: Probe) -> RuleResult:
    budget = _policy(probe).manifest_tokens
    if budget is None:
        return RuleResult.not_applicable(
            "no manifest token budget was supplied; pass --max-manifest-tokens to "
            "measure this. Reported as not-applicable rather than passing, because "
            "a pass would read as 'measured and fine'"
        )
    tools = _tools(probe)
    if tools is None:
        return RuleResult.not_applicable("tools/list did not return a tool list")

    total, per_tool = manifest_cost(tools)
    largest_first = sorted(per_tool, key=lambda t: -t.tokens)[:5]
    breakdown = ", ".join(f"{t.name}={t.tokens}" for t in largest_first)
    if total > budget:
        return RuleResult.failed(
            f"the manifest costs {total} tokens against a budget of {budget}, "
            f"across {len(per_tool)} tool(s). {tolerance_note(total)}",
            evidence=f"largest: {breakdown}",
        )
    return RuleResult.passed(
        f"{total} tokens across {len(per_tool)} tool(s), within the {budget} budget. "
        f"{tolerance_note(total)}",
        evidence=f"largest: {breakdown}",
    )


@rule(
    id="SENTINEL/OPS/per-tool-token-budget",
    title="no single tool exceeds the operator's per-tool token budget",
    severity=Severity.MUST,
    rationale=(
        "A manifest can sit inside its total budget while one tool consumes most of "
        "it, which is the shape that makes a server hard to mount alongside anything "
        "else. Checking the total alone would let that pass, and the total is the "
        "number a team notices only after they have added the second server."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation=("Split the tool, or move its schema's repeated structure behind a local $ref."),
    introduced_in="0.3.0",
)
def per_tool_token_budget(probe: Probe) -> RuleResult:
    budget = _policy(probe).per_tool_tokens
    if budget is None:
        return RuleResult.not_applicable(
            "no per-tool token budget was supplied; pass --max-tool-tokens"
        )
    tools = _tools(probe)
    if tools is None:
        return RuleResult.not_applicable("tools/list did not return a tool list")

    _, per_tool = manifest_cost(tools)
    over = [t for t in per_tool if t.tokens > budget]
    if over:
        worst = ", ".join(f"{t.name}={t.tokens}" for t in sorted(over, key=lambda t: -t.tokens))
        return RuleResult.failed(
            f"{len(over)} of {len(per_tool)} tool(s) exceed the {budget}-token "
            f"per-tool budget: {worst}",
            evidence=worst,
        )
    largest = max(per_tool, key=lambda t: t.tokens, default=None)
    detail = (
        f"all {len(per_tool)} tool(s) are within the {budget}-token budget"
        if largest is None
        else (
            f"all {len(per_tool)} tool(s) are within the {budget}-token budget; "
            f"largest is {largest.name} at {largest.tokens}"
        )
    )
    return RuleResult.passed(detail)


@rule(
    id="SENTINEL/OPS/tool-descriptions-are-distinct",
    title="no two tools share an identical description",
    severity=Severity.MUST,
    rationale=(
        "A description is the only thing a model has to choose between two tools. Two "
        "tools carrying identical text are indistinguishable at selection time, so the "
        "model picks by name or by order, and the manifest pays for the same prose "
        "twice. This is the cheapest real defect a manifest can have."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Give each tool a description that states what distinguishes it from its "
        "neighbours, or merge the tools if nothing does."
    ),
    introduced_in="0.3.0",
)
def tool_descriptions_are_distinct(probe: Probe) -> RuleResult:
    tools = _tools(probe)
    if tools is None:
        return RuleResult.not_applicable("tools/list did not return a tool list")

    _, per_tool = manifest_cost(tools)
    seen: dict[str, list[str]] = {}
    for cost in per_tool:
        text = cost.description.strip()
        if len(text) < _DUPLICATE_MIN_LENGTH:
            # Too short to be a meaningful duplicate. Two tools both described
            # as "Read a file." is a style problem, not a selection hazard, and
            # flagging it would make this rule noise.
            continue
        seen.setdefault(text, []).append(cost.name)

    collisions = {text: names for text, names in seen.items() if len(names) > 1}
    if collisions:
        wasted = sum(len(names) - 1 for names in collisions.values())
        groups = "; ".join(", ".join(names) for names in collisions.values())
        return RuleResult.failed(
            f"{len(collisions)} description(s) are shared by more than one tool, "
            f"{wasted} duplicate copy/copies in the manifest: {groups}",
            evidence=groups,
        )
    return RuleResult.passed(
        f"{len(per_tool)} tool(s) carry distinct descriptions "
        f"(checked at {_DUPLICATE_MIN_LENGTH}+ characters)"
    )


@rule(
    id="SENTINEL/OPS/schema-depth-budget",
    title="no tool schema nests deeper than the operator's budget",
    severity=Severity.MUST,
    rationale=(
        "Nesting depth is a proxy for how much a caller must read to use a tool, and "
        "deep schemas are where manifest size comes from without anyone noticing. "
        "Depth is measured on the schema as served: this does not resolve $ref, "
        "because following a URL the scan target supplied is a request this harness "
        "declines to make. A schema hiding its depth behind a remote $ref therefore "
        "measures shallow, which is the safe direction to be wrong in."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Flatten the schema, or lift repeated sub-objects into local $defs so the "
        "structure is stated once."
    ),
    introduced_in="0.3.0",
)
def schema_depth_budget(probe: Probe) -> RuleResult:
    budget = _policy(probe).schema_depth
    if budget is None:
        return RuleResult.not_applicable(
            "no schema depth budget was supplied; pass --max-schema-depth"
        )
    tools = _tools(probe)
    if tools is None:
        return RuleResult.not_applicable("tools/list did not return a tool list")

    _, per_tool = manifest_cost(tools)
    over = [t for t in per_tool if t.depth > budget]
    if over:
        worst = ", ".join(f"{t.name}={t.depth}" for t in sorted(over, key=lambda t: -t.depth))
        return RuleResult.failed(
            f"{len(over)} tool schema(s) nest deeper than {budget}: {worst}",
            evidence=worst,
        )
    deepest = max((t.depth for t in per_tool), default=0)
    return RuleResult.passed(
        f"all {len(per_tool)} tool schema(s) are within depth {budget}; deepest is {deepest}"
    )
