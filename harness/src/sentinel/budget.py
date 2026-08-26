"""What a server's tool manifest costs an agent before it does any work.

An agent wired to several MCP servers pays for every tool description in every
manifest, on every initialization, before the user's first message is read.
That cost is invisible in the protocol: nothing in the specification bounds a
manifest's size, and a server that is perfectly conformant can still be
expensive enough to crowd a context window on its own.

This module prices that, so it can be gated in CI the way any other budget is.

WHY THE BUDGETS HAVE NO DEFAULTS
--------------------------------
Every threshold here is supplied by the operator or the rule does not run. A
default budget would be this project inventing a number it cannot justify: the
right ceiling depends on the model's context window, how many servers are
mounted, and how much of the window the team is willing to spend before the
conversation starts. None of those are knowable from the wire.

That is also why a rule with no budget returns NOT_APPLICABLE rather than
passing. A pass reads as "measured and fine"; this is "not measured".

ON THE TOLERANCE
----------------
`sentinel/approx-v1` is an approximation, stated in `sentinel.tokens` as landing
within roughly 10% of cl100k_base on JSON. That is ample for the before/after
comparison it was built for, and it is a real error bar on a red build: a
manifest measured at 9,500 tokens against a 10,000 budget is not reliably under
it. Every failure detail below states the tolerance, so nobody reads a budget
verdict as more precise than the method behind it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sentinel.tokens import TOKENIZER_NAME, estimate_tokens

__all__ = [
    "TOKENIZER_TOLERANCE",
    "BudgetPolicy",
    "ToolCost",
    "manifest_cost",
    "schema_depth",
]

#: The tokenizer's stated accuracy against cl100k_base on JSON, as a fraction.
#: Printed next to any budget verdict so the reader can see the error bar.
TOKENIZER_TOLERANCE = 0.10


@dataclass(frozen=True, slots=True)
class BudgetPolicy:
    """Operator-supplied ceilings. `None` means "do not check this".

    Carried on the Probe rather than read from a module global so that two
    scans in one process cannot silently share a policy, and so a rule's inputs
    are all reachable from its one argument.
    """

    manifest_tokens: int | None = None
    per_tool_tokens: int | None = None
    schema_depth: int | None = None

    @property
    def any_set(self) -> bool:
        return any(
            v is not None for v in (self.manifest_tokens, self.per_tool_tokens, self.schema_depth)
        )


@dataclass(frozen=True, slots=True)
class ToolCost:
    """One tool's share of the manifest, priced the way the broker prices it."""

    name: str
    tokens: int
    description: str
    depth: int


def _canonical(value: Any) -> str:
    """Serialize for counting.

    Key order and indentation do not change the count -- the tokenizer charges
    per run and per punctuation mark, and both are order-invariant -- so sorting
    keys here costs nothing and makes the number stable across servers that
    happen to emit their JSON differently.

    Numbers are the exception worth knowing about: Python does not round-trip
    JSON number literals (`1e3` decodes and re-encodes as `1000.0`), so this
    counts the DECODED manifest, not the bytes on the wire. For schema keywords
    that carry numbers -- `multipleOf`, `maximum` -- the two can differ by a
    token or two. Stated here rather than silently absorbed.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def schema_depth(value: Any, _depth: int = 0) -> int:
    """Maximum nesting depth of a decoded JSON value.

    Depth is a proxy for how much a caller has to read to use a tool. It does
    not follow `$ref`: resolving a reference the scan target supplied would
    mean fetching a URL the target chose, which is the same request-forgery
    this project declines to make elsewhere. A schema whose depth is hidden
    behind a remote `$ref` therefore measures shallow, and that is the safe
    direction to be wrong in.
    """
    if isinstance(value, dict):
        if not value:
            return _depth
        return max(schema_depth(v, _depth + 1) for v in value.values())
    if isinstance(value, list):
        if not value:
            return _depth
        return max(schema_depth(v, _depth + 1) for v in value)
    return _depth


def manifest_cost(tools: list[Any]) -> tuple[int, list[ToolCost]]:
    """Price a `tools/list` payload under TOKENIZER_NAME.

    Returns the whole-manifest count and a per-tool breakdown. The per-tool
    figure concatenates name, description and both schemas exactly as
    `countTokens` does in broker/internal/registry/tokens.go, so a number from
    either side of the project is the same number.
    """
    per_tool: list[ToolCost] = []
    for entry in tools:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", ""))
        description = str(entry.get("description", ""))
        parts = (
            name,
            description,
            _canonical(entry.get("inputSchema", {})),
            _canonical(entry.get("outputSchema", {})),
        )
        per_tool.append(
            ToolCost(
                name=name,
                tokens=estimate_tokens("".join(parts)),
                description=description,
                depth=max(
                    schema_depth(entry.get("inputSchema", {})),
                    schema_depth(entry.get("outputSchema", {})),
                ),
            )
        )
    manifest_tokens = estimate_tokens(_canonical({"tools": tools}))
    return manifest_tokens, per_tool


def tolerance_note(tokens: int) -> str:
    """The error bar on a count, in the words a reader needs to act on it."""
    margin = round(tokens * TOKENIZER_TOLERANCE)
    return (
        f"{TOKENIZER_NAME} is an approximation within roughly "
        f"{int(TOKENIZER_TOLERANCE * 100)}% of cl100k_base on JSON, so treat this "
        f"as {tokens} +/- {margin}"
    )
