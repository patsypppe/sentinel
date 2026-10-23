"""Benchmark: lint a hand-picked set of widely used, published MCP servers.

Each server is started the way its README says (npx / uvx, dummy credentials where a token is
required just to start), its tool manifest is read, and Sentinel's manifest rules are run. The
output is aggregate: how many servers, how many tools, and what share break each rule.

    uv run python benchmarks/popular_servers.py

Not "the top N by stars": there is no registry API in reach, so this is a list chosen to span
official reference servers, vendor servers and community servers. The list is in this file.
A server that does not start within the timeout is counted as such, never dropped silently.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shlex
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from sentinel.catalog.base import Outcome
from sentinel.grade import LINT_RULES, run_scan
from sentinel.probe.client import Probe

HERE = pathlib.Path(__file__).resolve().parent
DUMMY = "sentinel-benchmark-dummy"


@dataclass
class Server:
    name: str
    command: str
    env: dict[str, str] = field(default_factory=dict)


NPX = "npx -y "
UVX = "uvx "
SERVERS = [
    Server("server-memory", NPX + "@modelcontextprotocol/server-memory"),
    Server("server-filesystem", NPX + "@modelcontextprotocol/server-filesystem /tmp"),
    Server("server-everything", NPX + "@modelcontextprotocol/server-everything"),
    Server("server-sequential-thinking", NPX + "@modelcontextprotocol/server-sequential-thinking"),
    Server("server-puppeteer", NPX + "@modelcontextprotocol/server-puppeteer"),
    Server(
        "server-github",
        NPX + "@modelcontextprotocol/server-github",
        {"GITHUB_PERSONAL_ACCESS_TOKEN": DUMMY},
    ),
    Server(
        "server-brave-search",
        NPX + "@modelcontextprotocol/server-brave-search",
        {"BRAVE_API_KEY": DUMMY},
    ),
    Server(
        "server-slack",
        NPX + "@modelcontextprotocol/server-slack",
        {"SLACK_BOT_TOKEN": DUMMY, "SLACK_TEAM_ID": DUMMY},
    ),
    Server(
        "server-google-maps",
        NPX + "@modelcontextprotocol/server-google-maps",
        {"GOOGLE_MAPS_API_KEY": DUMMY},
    ),
    Server("playwright-mcp", NPX + "@playwright/mcp@latest"),
    Server("context7", NPX + "@upstash/context7-mcp"),
    Server("notion", NPX + "@notionhq/notion-mcp-server", {"NOTION_TOKEN": DUMMY}),
    Server("firecrawl", NPX + "firecrawl-mcp", {"FIRECRAWL_API_KEY": DUMMY}),
    Server("chrome-devtools", NPX + "chrome-devtools-mcp@latest"),
    Server("desktop-commander", NPX + "@wonderwhy-er/desktop-commander"),
    Server("tavily", NPX + "tavily-mcp", {"TAVILY_API_KEY": DUMMY}),
    Server("exa", NPX + "exa-mcp-server", {"EXA_API_KEY": DUMMY}),
    Server("figma-developer", NPX + "figma-developer-mcp --stdio", {"FIGMA_API_KEY": DUMMY}),
    Server("mcp-server-kubernetes", NPX + "mcp-server-kubernetes"),
    Server("browser-tools", NPX + "@agentdeskai/browser-tools-mcp@latest"),
    Server("playwright-executeautomation", NPX + "@executeautomation/playwright-mcp-server"),
    Server("mcp-server-fetch", UVX + "mcp-server-fetch"),
    Server("mcp-server-git", UVX + "mcp-server-git --repository /tmp"),
    Server("mcp-server-time", UVX + "mcp-server-time"),
    Server("markitdown", UVX + "markitdown-mcp"),
    Server("duckduckgo", UVX + "duckduckgo-mcp-server"),
    Server("arxiv", UVX + "arxiv-mcp-server"),
    Server("basic-memory", UVX + "basic-memory mcp"),
    Server("aws-documentation", UVX + "awslabs.aws-documentation-mcp-server@latest"),
]


def lint(server: Server, timeout: float) -> dict[str, object]:
    argv = shlex.split(server.command)
    key = "stdio:" + server.command

    def factory() -> Probe:
        return Probe(key, timeout=timeout, legacy=True, command=argv, command_env=server.env)

    row: dict[str, object] = {"server": server.name, "command": server.command}
    try:
        with factory() as probe:
            result = probe.tools_list().result()
    except Exception as exc:  # a server that crashes the probe is a data point, not a crash
        row["status"] = f"error: {type(exc).__name__}"
        return row
    tools = (result or {}).get("tools")
    if not isinstance(tools, list) or not tools:
        row["status"] = "no tools listed (did not start, or listed none)"
        return row

    params = [
        (t.get("name"), p, d)
        for t in tools
        if isinstance(t, dict)
        for p, d in ((t.get("inputSchema") or {}).get("properties") or {}).items()
    ]
    row.update(
        status="ok",
        tools=len(tools),
        params=len(params),
        params_described=sum(
            1
            for _, _, d in params
            if isinstance(d, dict) and str(d.get("description") or "").strip()
        ),
        tools_described=sum(1 for t in tools if str(t.get("description") or "").strip()),
    )
    report = run_scan(
        key,
        only=set(LINT_RULES),
        probe_factory=factory,
        concurrency=2,
        detect_generation=False,
    )
    row["injection_kinds"] = sorted(
        {
            kind
            for f in report.findings
            if f.rule.id.endswith("tool-description-injection") and f.outcome is Outcome.FAIL
            for kind in re.findall(r"\[([a-z-]+)\]", f.result.detail)
        }
    )
    row["failed_rules"] = sorted(
        f.rule.id.split("/", 2)[2]
        for f in report.findings
        if f.outcome is Outcome.FAIL and not f.rule.is_deprecated
    )
    return row


def render(rows: list[dict[str, object]]) -> str:
    ok = [r for r in rows if r["status"] == "ok"]
    n = len(ok)
    tools = sum(int(r["tools"]) for r in ok)  # type: ignore[arg-type]
    params = sum(int(r["params"]) for r in ok)  # type: ignore[arg-type]
    described = sum(int(r["params_described"]) for r in ok)  # type: ignore[arg-type]
    undescribed_tools = tools - sum(int(r["tools_described"]) for r in ok)  # type: ignore[arg-type]

    def share(rule: str) -> int:
        return sum(1 for r in ok if rule in r["failed_rules"])  # type: ignore[operator]

    pct = 100 * (params - described) // max(params, 1)

    def kind_count(want: Callable[[str], bool]) -> int:
        return sum(1 for r in ok if any(want(k) for k in r["injection_kinds"]))  # type: ignore[attr-defined]

    out = [
        "# Benchmark: published MCP servers, linted",
        "",
        f"{len(rows)} servers attempted, **{n} started and listed tools** "
        f"({len(rows) - n} did not start, or listed no tools, within the timeout on this machine).",
        f"Across those {n} servers: **{tools} tools, {params} parameters**.",
        "",
        "| Finding | Servers affected | Detail |",
        "|---|---|---|",
        f"| Parameters with no description | **{share('parameters-are-described')} of {n}** "
        f"| {params - described} of {params} parameters ({pct}%) |",
        f"| Stub or missing tool description | **{share('description-states-purpose')} of {n}** "
        f"| {undescribed_tools} tools have no description at all |",
        f"| Tool list not in a stable order | {share('tools-list-is-deterministic')} of {n} | |",
        f"| Illegal characters in a tool name | {share('tool-names-well-formed')} of {n} | |",
        f"| Hidden characters or instruction-override text in a description | "
        f"{kind_count(lambda k: k != 'sensitive-path')} of {n} | |",
        f"| Description mentions a credential path (`.env`, `.aws`) | "
        f"{kind_count(lambda k: k == 'sensitive-path')} of {n} | usually benign, e.g. a warning |",
        "",
        "## Per server",
        "",
        "| Server | Tools | Params described | Rules failed |",
        "|---|---|---|---|",
    ]
    for r in rows:
        if r["status"] != "ok":
            out.append(f"| {r['server']} | - | - | {r['status']} |")
        else:
            out.append(
                f"| {r['server']} | {r['tools']} | {r['params_described']}/{r['params']} "
                f"| {', '.join(r['failed_rules']) or 'none'} |"  # type: ignore[arg-type]
            )
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=90.0)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out", type=pathlib.Path, default=HERE / "POPULAR_SERVERS.md")
    args = ap.parse_args()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows = list(pool.map(lambda s: lint(s, args.timeout), SERVERS))
    args.out.write_text(render(rows))
    args.out.with_suffix(".json").write_text(json.dumps(rows, indent=2) + "\n")
    print(render(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
