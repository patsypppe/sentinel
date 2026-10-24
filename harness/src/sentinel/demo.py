"""`sentinel demo`: scan two built-in practice servers, no setup.

One server has deliberate mistakes and one follows the rules, so a newcomer sees a
failing scan and a passing scan in a few seconds and learns what the output means.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager

from sentinel.fixtures_path import fixtures_dir

SHOWN_FAILURES = 4


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextmanager
def _practice_server(profile: str) -> Iterator[str]:
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", f"server.{profile}", str(port)],
        cwd=fixtures_dir(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError(f"the {profile} practice server did not start")
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def _scan(endpoint: str) -> dict[str, object]:
    done = subprocess.run(
        [sys.executable, "-m", "sentinel.cli", "scan", "--endpoint", endpoint, "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    report: dict[str, object] = json.loads(done.stdout)
    return report


def _show(title: str, blurb: str, report: dict[str, object]) -> bool:
    summary = report["summary"]
    assert isinstance(summary, dict)
    must, should = summary["must"], summary["should"]
    failing = summary["gating"]["failing"]
    print(f"\n=== {title} ===\n{blurb}")
    print(
        f"  required rules (MUST):  {must['pass']} pass, {must['fail']} fail, "
        f"{must['indeterminate']} could not be checked from outside"
    )
    print(f"  advice (SHOULD):        {should['pass']} pass, {should['fail']} fail")
    findings = report["findings"]
    assert isinstance(findings, list)
    fails = [f for f in findings if f["outcome"] == "fail" and f["severity"] == "must"]
    for f in fails[:SHOWN_FAILURES]:
        print(f"\n  FAIL  {f['ruleId'].split('/', 2)[2]}\n        {f['detail'][:110]}")
    if len(fails) > SHOWN_FAILURES:
        print(f"\n  ... and {len(fails) - SHOWN_FAILURES} more")
    print(f"\n  verdict: {'FAIL (exit code 1)' if failing else 'PASS (exit code 0)'}")
    return not failing


def run_demo() -> int:
    print("Sentinel demo: starting two practice MCP servers on your machine...")
    with _practice_server("nonconformant") as bad, _practice_server("conformant") as good:
        _show(
            "Server A: has deliberate mistakes",
            "Sentinel sends it test requests and checks every answer against the spec.",
            _scan(bad),
        )
        _show(
            "Server B: follows the rules",
            "Same scan, different server.",
            _scan(good),
        )
    print(
        "\nNext: point it at your own server:\n"
        "  sentinel scan --endpoint https://your-server.example/mcp --gate must"
    )
    return 0
