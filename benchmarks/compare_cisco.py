"""Benchmark: tool-description poisoning, Sentinel against Cisco's open-source `mcp-scanner`.

Three sets of tool definitions:
  * 15 poisoned tools written after published attack patterns (explicit, hidden-character, and
    evasive ones a keyword approach is expected to miss);
  * 6 hard negatives: honest descriptions that look scary (a warning, a ".env" mention, "MUST");
  * every tool from the published servers `popular_servers.py` collects, taken as benign.

Both tools are run on the same JSON. Cisco's analyzer here is its offline YARA rule set (no API
key, no LLM); its cloud and LLM analyzers are not compared. Needs `uvx`, and network once.

    uv run python benchmarks/popular_servers.py --dump-tools /tmp/tools
    uv run python benchmarks/compare_cisco.py --real-tools /tmp/tools
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile

from sentinel.catalog.beyond.security import injection_findings

HERE = pathlib.Path(__file__).resolve().parent


def cisco_flags(tools: list[dict[str, object]]) -> set[str]:
    """Names of the tools Cisco's offline YARA analyzer calls unsafe."""
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "tools.json"
        path.write_text(json.dumps({"tools": tools}))
        done = subprocess.run(
            [
                "uvx",
                "--from",
                "cisco-ai-mcp-scanner",
                "mcp-scanner",
                "--analyzers",
                "yara",
                "--raw",
                "static",
                "--tools",
                str(path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    out = done.stdout
    data = json.loads(out[out.index("[") :])
    return {str(d["tool_name"]) for d in data if not d.get("is_safe", True)}


def sentinel_flags(tools: list[dict[str, object]], *, core_only: bool) -> set[str]:
    flagged = set()
    for tool in tools:
        kinds = {kind for kind, _, _ in injection_findings(tool)}  # type: ignore[arg-type]
        if core_only:
            kinds.discard("sensitive-path")
        if kinds:
            flagged.add(str(tool["name"]))
    return flagged


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--real-tools", type=pathlib.Path, required=True)
    ap.add_argument("--out", type=pathlib.Path, default=HERE / "SECURITY_COMPARE.md")
    args = ap.parse_args()

    corpus = json.loads((HERE / "poisoning_corpus.json").read_text())
    poisoned = [dict(p["tool"], name=p["id"]) for p in corpus["poisoned"]]
    kind = {p["id"]: p["kind"] for p in corpus["poisoned"]}
    hard = [dict(h["tool"], name=h["id"]) for h in corpus["hard_benign"]]
    real: list[dict[str, object]] = []
    for f in sorted(args.real_tools.glob("*.json")):
        for tool in json.loads(f.read_text())["tools"]:
            real.append(dict(tool, name=f"{f.stem}::{tool.get('name', '?')}"))

    results: dict[str, dict[str, set[str]]] = {}
    for label, tools in (("poisoned", poisoned), ("hard", hard), ("real", real)):
        results[label] = {
            "Sentinel (all categories)": sentinel_flags(tools, core_only=False),
            "Sentinel (without credential-path mentions)": sentinel_flags(tools, core_only=True),
            "Cisco mcp-scanner (YARA, offline)": cisco_flags(tools),
        }

    def recall(tool_set: set[str], which: str) -> str:
        ids = [i for i, k in kind.items() if which in ("all", k)]
        return f"{len(tool_set & set(ids))}/{len(ids)}"

    lines = [
        "# Tool-description poisoning: Sentinel vs Cisco mcp-scanner (offline YARA)",
        "",
        f"{len(poisoned)} poisoned tools, {len(hard)} hard negatives, {len(real)} real tools from "
        "published servers (taken as benign, then the flagged ones read by hand).",
        "",
        "| Tool | Poisoned caught: explicit | hidden characters | evasive | all | Hard negatives "
        "wrongly flagged | Real tools flagged |",
        "|---|---|---|---|---|---|---|",
    ]
    for name in results["poisoned"]:
        p, h, r = results["poisoned"][name], results["hard"][name], results["real"][name]
        lines.append(
            f"| {name} | {recall(p, 'explicit')} | {recall(p, 'hidden')} | {recall(p, 'evasive')} "
            f"| {recall(p, 'all')} | {len(h)}/{len(hard)} | {len(r)}/{len(real)} |"
        )
    lines += ["", "Missed by each (poisoned):", ""]
    for name, flagged in results["poisoned"].items():
        missed = sorted(set(kind) - flagged)
        lines.append(f"- {name}: {', '.join(missed) or 'none'}")
    args.out.write_text("\n".join(lines) + "\n")
    args.out.with_suffix(".json").write_text(
        json.dumps({a: {b: sorted(c) for b, c in d.items()} for a, d in results.items()}, indent=1)
    )
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
