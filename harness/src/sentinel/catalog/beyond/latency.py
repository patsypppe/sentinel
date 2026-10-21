"""Beyond-spec: how long the read-only methods take.

The specification sets no latency bound, so a slow server is not non-conformant.
It is slow, and an agent that waits on `tools/list` before every conversation
inherits the delay. `--gate ops` makes the budget enforceable; unset, the rule
reports not-applicable rather than passing, because a pass would read as
"measured and fine".
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable

from sentinel.budget import BudgetPolicy
from sentinel.catalog.base import RuleResult, Severity, Verifiability, rule
from sentinel.probe.client import Probe
from sentinel.probe.transport import RawResponse

SAMPLES = 20


def p95(values: list[float]) -> float:
    """Nearest-rank 95th percentile. Raises on an empty list."""
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


@rule(
    id="SENTINEL/OPS/latency-budget",
    title="the read-only methods answer within the operator's p95 budget",
    severity=Severity.MUST,
    rationale=(
        "An agent waits on server/discover and tools/list before it can start a "
        "conversation, and again whenever it refreshes a manifest. Nothing in the "
        "specification bounds how long those take, so a conformant server can still "
        "make every session feel slow. The ceiling is the operator's, because the "
        "right number depends on where the client runs and what it is competing with."
    ),
    verifiability=Verifiability.BLACK_BOX,
    remediation=(
        "Cache the manifest in memory, avoid per-request database reads on "
        "tools/list, and check for a cold-path (first request) cost that a warm-up "
        "request would remove."
    ),
    introduced_in="0.4.0",
    exclusive=True,
)
def latency_budget(probe: Probe) -> RuleResult:
    budget = getattr(probe, "budgets", BudgetPolicy()).latency_p95_ms
    if budget is None:
        return RuleResult.not_applicable(
            "no latency budget was supplied; pass --max-p95-ms to measure this. Reported "
            "as not-applicable rather than passing, because a pass would read as "
            "'measured and fine'"
        )
    senders: list[tuple[str, Callable[[], RawResponse]]] = [
        ("server/discover", probe.discover),
        ("tools/list", probe.tools_list),
    ]
    worst: tuple[str, float] | None = None
    for name, send in senders:
        samples: list[float] = []
        for _ in range(SAMPLES):
            started = time.perf_counter()
            response = send()
            elapsed = (time.perf_counter() - started) * 1000
            if not response.reached_server:
                return RuleResult.indeterminate(
                    f"{name} was unreachable while timing it: {response.transport_error}"
                )
            samples.append(elapsed)
        measured = p95(samples)
        if worst is None or measured > worst[1]:
            worst = (name, measured)
    assert worst is not None
    if worst[1] > budget:
        return RuleResult.failed(
            f"{worst[0]} p95 was {worst[1]:.0f} ms over {SAMPLES} calls, above the "
            f"{budget} ms budget",
            evidence=f"{worst[0]} p95 {worst[1]:.1f} ms",
            key=worst[0],
        )
    return RuleResult.passed(
        f"p95 of {worst[1]:.0f} ms on the slowest method ({worst[0]}), within {budget} ms"
    )
