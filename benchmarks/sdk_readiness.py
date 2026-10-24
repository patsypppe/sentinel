"""Benchmark: what does Sentinel say about servers people actually build with?

Scans servers built with the official SDKs, unmodified, and prints what it found. These are
not planted bugs: whatever Sentinel reports is a real divergence between the server and the
specification text (or a Sentinel false positive, which is why every FAIL is shown with its
detail so it can be checked against the spec).

    uv run python benchmarks/sdk_readiness.py --conformance ~/src/conformance
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

HERE = pathlib.Path(__file__).resolve().parent


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait(port: int) -> None:
    for _ in range(200):
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


def servers(conformance: pathlib.Path) -> list[tuple[str, list[str], pathlib.Path]]:
    ts = conformance / "examples" / "servers" / "typescript"
    return [
        (
            "MCP Python SDK 2.x (MCPServer, streamable HTTP)",
            ["uv", "run", "--with", "mcp", "python", str(HERE / "servers" / "pysdk_demo.py")],
            HERE,
        ),
        (
            "Official conformance reference server (TypeScript SDK)",
            ["npx", "tsx", "everything-server.ts"],
            ts,
        ),
    ]


def run(conformance: pathlib.Path) -> str:
    out = ["# Benchmark: servers built with the official SDKs", ""]
    for name, argv, cwd in servers(conformance):
        port = _free_port()
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
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
        s = report["summary"]
        assert isinstance(s, dict)
        findings = report["findings"]
        assert isinstance(findings, list)
        gen = (report.get("target") or {}).get("generation")  # type: ignore[attr-defined]
        out += [
            f"## {name}",
            "",
            f"Protocol generation detected: `{gen}`. "
            f"MUST rules: {s['must']['pass']} pass, {s['must']['fail']} fail, "
            f"{s['must']['indeterminate']} not checkable from outside. "
            f"SHOULD: {s['should']['pass']} pass, {s['should']['fail']} fail.",
            "",
        ]
        fails = [f for f in findings if f["outcome"] == "fail"]
        if fails:
            out += ["| Rule | What Sentinel saw |", "|---|---|"]
            for f in fails:
                rid = f["ruleId"].replace("MCP/2026-07-28/", "")
                out.append(f"| `{rid}` | {str(f['detail'])[:150].replace('|', '/')} |")
            out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--conformance", type=pathlib.Path, required=True)
    ap.add_argument("--out", type=pathlib.Path, default=HERE / "SDK_RESULTS.md")
    args = ap.parse_args()
    text = run(args.conformance)
    args.out.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
