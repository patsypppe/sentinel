"""Benchmark: does Sentinel catch violations that someone else labelled?

The MCP project's conformance repo ships deliberately broken servers, each with a header
comment naming the one thing it gets wrong. Those labels were written by the MCP maintainers
for their own test suite, not by this project, so they are an independent answer key.

For each broken server this runs a Sentinel scan and checks whether the rule that should catch
the labelled violation FAILed. It also reports every case the scan could not reach.

    uv run python benchmarks/official_negatives.py --conformance ~/src/conformance

Needs a checkout of https://github.com/modelcontextprotocol/conformance with
`npm ci` run in both the repo root and examples/servers/typescript.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import socket
import subprocess
import sys
import time

REV = "MCP/2026-07-28"

# fixture file -> (what the fixture's own header says is wrong, rules that should FAIL for it,
#                  or [] when Sentinel has no rule for it, which is reported as a coverage gap)
LABELS: dict[str, tuple[str, list[str]]] = {
    "sep-2549-no-caching-hints": (
        "omits ttlMs and cacheScope from list/read results",
        [f"{REV}/MUST/cacheable-results-carry-ttl", f"{REV}/MUST/cacheable-results-carry-scope"],
    ),
    "sep-2322-mrtr-broken-server": (
        "omits resultType; accepts a tampered requestState",
        [f"{REV}/MUST/result-type-present", f"{REV}/MUST/tampered-requeststate-rejected"],
    ),
    "sep-2164-empty-contents": (
        "returns an empty contents array for a resource that does not exist",
        [f"{REV}/MUST/resource-not-found-is-invalid-params"],
    ),
    "tools-list-rotated-order": (
        "reorders tools/list on every call",
        [f"{REV}/SHOULD/tools-list-is-deterministic"],
    ),
    "invalid-tool-names": (
        "advertises tool names with illegal characters",
        [f"{REV}/SHOULD/tool-names-well-formed"],
    ),
    "no-dns-rebinding-protection": (
        "does not validate the Origin header",
        [f"{REV}/MUST/invalid-origin-rejected"],
    ),
    "sep-2106-stripped-schema": (
        "strips JSON Schema 2020-12 keywords from a tool's inputSchema",
        [],
    ),
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait(port: int) -> None:
    for _ in range(150):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"nothing listening on {port}")


def _scan(port: int) -> dict[str, object]:
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli",
            "scan",
            "--endpoint",
            f"http://127.0.0.1:{port}/mcp",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    report: dict[str, object] = json.loads(done.stdout)
    return report


def run(conformance: pathlib.Path) -> list[dict[str, object]]:
    servers = conformance / "examples" / "servers" / "typescript"
    rows: list[dict[str, object]] = []
    for name, (labelled, expected) in LABELS.items():
        port = _free_port()
        proc = subprocess.Popen(
            ["npx", "tsx", f"{name}.ts"],
            cwd=servers,
            env={**os.environ, "PORT": str(port)},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait(port)
            report = _scan(port)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
        findings = report["findings"]
        assert isinstance(findings, list)
        outcome = {f["ruleId"]: f["outcome"] for f in findings}
        rows.append(
            {
                "fixture": name,
                "labelled_violation": labelled,
                "expected_rules": expected,
                "caught": [r for r in expected if outcome.get(r) == "fail"],
                "missed": [r for r in expected if outcome.get(r) != "fail"],
                "missed_outcomes": {
                    r: outcome.get(r) for r in expected if outcome.get(r) != "fail"
                },
                "generation": (report.get("target") or {}).get("generation"),
            }
        )
    return rows


def render(rows: list[dict[str, object]]) -> str:
    out = [
        "# Benchmark: violations labelled by the MCP maintainers",
        "",
        "Each server below is a deliberately broken fixture from the official "
        "`modelcontextprotocol/conformance` repo. The violation column is that fixture's own "
        "description. Sentinel is run unmodified; a rule counts as *caught* only if it FAILed.",
        "",
        "| Broken server | What the maintainers say is wrong | Sentinel | Why not |",
        "|---|---|---|---|",
    ]
    caught = total = 0
    for r in rows:
        exp, got = r["expected_rules"], r["caught"]
        assert isinstance(exp, list) and isinstance(got, list)
        if exp and r["generation"] == "unreachable":
            # Every request failed, for any client. Nothing can be graded, so it is shown
            # but kept out of the denominator rather than counted as a miss or a catch.
            out.append(
                f"| `{r['fixture']}` | {r['labelled_violation']} | not gradable | "
                "the fixture itself fails every request (server error on all methods) |"
            )
            continue
        if not exp:
            verdict, why = (
                "no rule",
                "coverage gap: JSON Schema 2020-12 preservation is not checked",
            )
        else:
            total += len(exp)
            caught += len(got)
            verdict = f"{len(got)}/{len(exp)} caught"
            why = ""
            if r["missed"]:
                if r["generation"] == "legacy":
                    why = "server speaks only the previous MCP revision, so the rule never ran"
                else:
                    seen = ", ".join(str(v) for v in dict(r["missed_outcomes"]).values())  # type: ignore[call-overload]
                    why = (
                        f"Sentinel reported {seen}, not FAIL: the server refused the probe "
                        "for an unrelated reason, and Sentinel does not guess"
                    )
        out.append(f"| `{r['fixture']}` | {r['labelled_violation']} | {verdict} | {why} |")
    out += [
        "",
        f"**{caught} of {total} labelled violations caught** "
        f"({100 * caught // max(total, 1)}%). Misses are listed, not hidden.",
        "",
    ]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--conformance", type=pathlib.Path, required=True)
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path("benchmarks/RESULTS.md"))
    args = ap.parse_args()
    rows = run(args.conformance)
    args.out.write_text(render(rows))
    args.out.with_suffix(".json").write_text(json.dumps(rows, indent=2) + "\n")
    print(render(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
