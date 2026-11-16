"""`toolgauge lint --command` lints a server that only speaks stdio."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap

import pytest

pytestmark = pytest.mark.unit

SERVER = textwrap.dedent(
    """
    import json, sys
    TOOLS = [
        {"name": "lookup_order", "description": "Look up an order by its id.",
         "inputSchema": {"type": "object", "properties": {"filters": {"type": "object"}}}},
    ]
    print("starting up", flush=True)  # a banner on stdout is not a reply
    for line in sys.stdin:
        msg = json.loads(line)
        if "id" not in msg:
            continue
        if msg["method"] == "initialize":
            result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}}
        elif msg["method"] == "tools/list":
            result = {"tools": TOOLS}
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                              "error": {"code": -32601, "message": "no"}}), flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
    """
)


def test_lint_reads_a_stdio_servers_manifest_and_reports_the_undescribed_parameter(
    tmp_path: pytest.TempPathFactory,
) -> None:
    script = tmp_path / "server.py"  # type: ignore[operator]
    script.write_text(SERVER)
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "toolgauge.cli",
            "lint",
            "--command",
            f"{sys.executable} {script}",
            "--format",
            "json",
            "--timeout",
            "10",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    report = json.loads(done.stdout)
    outcome = {f["ruleId"]: f["outcome"] for f in report["findings"]}
    assert outcome["TOOLGAUGE/STYLE/parameters-are-described"] == "fail"
    assert outcome["MCP/2026-07-28/SHOULD/tool-names-well-formed"] == "pass"
    assert done.returncode == 1


def _lint(script: pytest.TempPathFactory, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "toolgauge.cli",
            "lint",
            "--command",
            f"{sys.executable} {script}",
            "--format",
            "json",
            "--timeout",
            "10",
            *args,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_lint_baseline_gates_only_on_failures_it_has_not_seen(
    tmp_path: pytest.TempPathFactory,
) -> None:
    script = tmp_path / "server.py"  # type: ignore[operator]
    script.write_text(SERVER)
    baseline = tmp_path / "lint-baseline.json"  # type: ignore[operator]

    first = _lint(script, "--write-baseline", str(baseline))
    assert first.returncode == 1
    recorded = json.loads(baseline.read_text())  # type: ignore[union-attr]
    assert recorded["findings"], "the fixture seeds a failure to record"

    adopted = _lint(script, "--baseline", str(baseline))
    assert adopted.returncode == 0
    report = json.loads(adopted.stdout)
    assert report["summary"]["gating"]["baselined"] == len(recorded["findings"])


def test_a_rule_absent_from_the_baseline_still_fails(tmp_path: pytest.TempPathFactory) -> None:
    rule_id = "TOOLGAUGE/STYLE/parameters-are-described"
    script = tmp_path / "server.py"  # type: ignore[operator]
    script.write_text(SERVER)
    baseline = tmp_path / "lint-baseline.json"  # type: ignore[operator]
    _lint(script, "--write-baseline", str(baseline))

    data = json.loads(baseline.read_text())  # type: ignore[union-attr]
    data["ruleIds"] = [rid for rid in data["ruleIds"] if rid != rule_id]
    data["findings"] = [f for f in data["findings"] if f["ruleId"] != rule_id]
    baseline.write_text(json.dumps(data))  # type: ignore[union-attr]

    result = _lint(script, "--baseline", str(baseline))
    assert result.returncode == 1
    report = json.loads(result.stdout)
    new = [f["ruleId"] for f in report["findings"] if f["ruleIsNewSinceBaseline"]]
    assert new == [rule_id]


def test_lint_starts_the_server_once_not_once_per_rule(tmp_path: pytest.TempPathFactory) -> None:
    counter = tmp_path / "starts.txt"  # type: ignore[operator]
    script = tmp_path / "server.py"  # type: ignore[operator]
    script.write_text(f"open({str(counter)!r}, 'a').write('x')\n" + SERVER)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "toolgauge.cli",
            "lint",
            "--command",
            f"{sys.executable} {script}",
            "--format",
            "json",
            "--timeout",
            "10",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    # One shared process, plus one extra connection for the two-connections consistency rule.
    assert len(counter.read_text()) <= 2
