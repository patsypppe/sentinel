"""Check functions shared between a deprecated rule and its successor.

When a rule's severity turns out to be wrong, the id is deprecated and a new one
published (HANDOFF §8.8). Both then need the same check. Keeping the function
here rather than duplicating it means the pair cannot silently disagree about
what it is measuring -- which would make the deprecation notice a lie.
"""

from __future__ import annotations

import hashlib

from sentinel.catalog.base import RuleResult
from sentinel.probe.client import KEY_SERVER_INFO, Probe


def server_info_echoed(probe: Probe) -> RuleResult:
    senders = [
        ("server/discover", probe.discover),
        ("tools/list", probe.tools_list),
        ("resources/list", probe.resources_list),
        ("resources/templates/list", probe.resource_templates_list),
        ("prompts/list", probe.prompts_list),
    ]
    missing: list[str] = []
    checked = 0

    for name, send in senders:
        result = send().result()
        if result is None:
            continue
        checked += 1
        meta = result.get("_meta")
        info = meta.get(KEY_SERVER_INFO) if isinstance(meta, dict) else None
        if not isinstance(info, dict) or not info.get("name"):
            # server/discover may report it at the top level instead.
            top = result.get("serverInfo")
            if isinstance(top, dict) and top.get("name"):
                continue
            missing.append(name)

    if checked == 0:
        return RuleResult.indeterminate("no endpoint returned a result to inspect")
    if missing:
        return RuleResult.failed(
            f"{len(missing)} of {checked} results omit serverInfo: {missing}",
            evidence=f"endpoints missing serverInfo: {missing}",
        )
    return RuleResult.passed(f"all {checked} results echo serverInfo")


def tools_list_deterministic(probe: Probe) -> RuleResult:
    # Twenty calls, not one hundred: enough that map iteration order will differ
    # if it is going to, without making a scan slow against a remote server.
    # The broker's own test suite runs the full hundred.
    digests: set[str] = set()
    orders: set[str] = set()

    for _ in range(20):
        result = probe.tools_list().result()
        if result is None:
            return RuleResult.not_applicable("tools/list did not return a result")
        tools = result.get("tools")
        if not isinstance(tools, list):
            return RuleResult.failed(f"tools is not an array: {tools!r}")
        names = [t.get("name") for t in tools if isinstance(t, dict)]
        orders.add(",".join(str(n) for n in names))
        digests.add(hashlib.sha256(str(tools).encode()).hexdigest())

    if len(orders) > 1:
        return RuleResult.failed(
            f"tools/list returned {len(orders)} different orderings across 20 calls",
            evidence=f"orderings observed: {sorted(orders)[:3]}",
        )
    if len(digests) > 1:
        return RuleResult.failed(
            f"tools/list returned {len(digests)} different tool payloads across 20 calls "
            "with the same ordering; some field varies between calls",
            evidence=f"{len(digests)} distinct digests",
        )
    return RuleResult.passed("20 calls to tools/list produced one distinct payload")


def tools_sorted_by_name(probe: Probe) -> RuleResult:
    result = probe.tools_list().result()
    if result is None:
        return RuleResult.not_applicable("tools/list did not return a result")

    tools = result.get("tools")
    if not isinstance(tools, list) or len(tools) < 2:
        return RuleResult.not_applicable("fewer than two tools to order")

    names = [t.get("name", "") for t in tools if isinstance(t, dict)]
    ordered = sorted(names, key=lambda n: str(n).encode())
    if names != ordered:
        return RuleResult.failed(
            f"tools are not in byte-wise name order: {names} (byte-wise would be {ordered})",
            evidence=f"served {names}, byte-wise {ordered}",
        )
    return RuleResult.passed(f"{len(names)} tools are in byte-wise name order")
