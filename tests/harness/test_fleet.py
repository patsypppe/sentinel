"""Fleet scanning: each target judged by its own gate, nothing silently green."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

from sentinel.config import load_policy
from sentinel.fleet import exit_code, load_fleet, rollup, scan_fleet
from sentinel.waivers import ConfigError

pytestmark = pytest.mark.unit

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def fleet_file(tmp_path: pathlib.Path, body: str, name: str = "fleet.yaml") -> pathlib.Path:
    path = tmp_path / name
    path.write_text(body)
    return path


def policy(tmp_path: pathlib.Path):
    (tmp_path / "sentinel.toml").write_text("")
    return load_policy(config=tmp_path / "sentinel.toml", env={})


def test_a_fleet_file_is_validated(tmp_path: pathlib.Path) -> None:
    with pytest.raises(ConfigError, match="non-empty `targets`"):
        load_fleet(fleet_file(tmp_path, "concurrency: 2\n"))
    with pytest.raises(ConfigError, match="missing 'endpoint'"):
        load_fleet(fleet_file(tmp_path, "targets:\n  - name: a\n"))
    with pytest.raises(ConfigError, match="duplicate target name"):
        load_fleet(
            fleet_file(
                tmp_path,
                "targets:\n  - {name: a, endpoint: http://x/mcp}\n  - {name: a, endpoint: http://y/mcp}\n",
            )
        )
    with pytest.raises(ConfigError, match="unknown key"):
        load_fleet(
            fleet_file(tmp_path, "targets:\n  - {name: a, endpoint: http://x/mcp, tokn: 1}\n")
        )
    with pytest.raises(ConfigError, match="not a gate"):
        load_fleet(
            fleet_file(tmp_path, "targets:\n  - {name: a, endpoint: http://x/mcp, gate: bad}\n")
        )
    with pytest.raises(ConfigError, match="at least 1"):
        load_fleet(
            fleet_file(
                tmp_path, "concurrency: 0\ntargets:\n  - {name: a, endpoint: http://x/mcp}\n"
            )
        )


def test_toml_fleets_work_too(tmp_path: pathlib.Path) -> None:
    fleet = load_fleet(
        fleet_file(
            tmp_path,
            'concurrency = 3\n[[targets]]\nname = "a"\n'
            'endpoint = "http://x/mcp"\ngate = "should"\n',
            "fleet.toml",
        )
    )
    assert fleet.concurrency == 3
    assert fleet.targets[0].gate == "should"


def test_each_target_is_judged_by_its_own_gate_and_the_worst_wins(
    conformant_endpoint: str, nonconformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    fleet = load_fleet(
        fleet_file(
            tmp_path,
            f"""
concurrency: 2
targets:
  - {{name: good, endpoint: "{conformant_endpoint}", gate: must}}
  - {{name: bad, endpoint: "{nonconformant_endpoint}", gate: must}}
""",
        )
    )
    results = scan_fleet(fleet, policy(tmp_path), env={})
    by_name = {r.target.name: r for r in results}
    assert by_name["good"].status == "pass"
    assert by_name["bad"].status == "fail"
    assert exit_code(results) == 1
    # Fingerprints use the target NAME, so a target keeps its identity if its URL moves.
    assert by_name["bad"].report is not None
    assert by_name["bad"].report.target == "name:bad"


def test_the_same_server_can_pass_one_gate_and_fail_another(
    nonconformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    fleet = load_fleet(
        fleet_file(
            tmp_path,
            f"""
targets:
  - {{name: lax, endpoint: "{nonconformant_endpoint}"}}
  - {{name: strict, endpoint: "{nonconformant_endpoint}", gate: must}}
""",
        )
    )
    by_name = {r.target.name: r for r in scan_fleet(fleet, policy(tmp_path), env={})}
    assert by_name["lax"].status == "pass", "no gate means report, not judge"
    assert by_name["strict"].status == "fail"


def test_an_unreachable_target_is_an_error_for_that_target_only(
    conformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    fleet = load_fleet(
        fleet_file(
            tmp_path,
            f"""
targets:
  - {{name: up, endpoint: "{conformant_endpoint}", gate: must}}
  - {{name: down, endpoint: "http://127.0.0.1:9/mcp", gate: must, timeout: 1}}
""",
        )
    )
    results = scan_fleet(fleet, policy(tmp_path), env={})
    by_name = {r.target.name: r for r in results}
    assert by_name["up"].status == "pass"
    assert by_name["down"].status == "error"
    assert "unreachable" in by_name["down"].error
    assert exit_code(results) == 2, "an error must never read as a pass"


def test_a_target_whose_credential_is_missing_is_not_scanned_anonymously(
    conformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    fleet = load_fleet(
        fleet_file(
            tmp_path,
            f'targets:\n  - {{name: t, endpoint: "{conformant_endpoint}", '
            "token_env: NOPE_TOKEN}\n",
        )
    )
    [result] = scan_fleet(fleet, policy(tmp_path), env={})
    assert result.status == "error"
    assert "NOPE_TOKEN" in result.error

    [ok] = scan_fleet(fleet, policy(tmp_path), env={"NOPE_TOKEN": "x"})
    assert ok.status == "pass"


def test_a_target_can_keep_its_own_waivers(
    nonconformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    probe = scan_fleet(
        load_fleet(
            fleet_file(
                tmp_path,
                f'targets:\n  - {{name: t, endpoint: "{nonconformant_endpoint}", gate: must}}\n',
            )
        ),
        policy(tmp_path),
        env={},
    )[0]
    assert probe.report is not None
    rules = [
        f.rule.id
        for f in probe.report.by_outcome_fail()
        if "/MUST/" in f.rule.id and f.rule.namespace.value == "MCP"
    ]
    (tmp_path / "vendor.toml").write_text(
        "".join(
            f'[[waivers]]\nrule = "{r}"\nreason = "vendor owns this, tracked upstream"\n'
            "expires_at = 2099-01-01\n"
            for r in rules
        )
    )
    fleet = load_fleet(
        fleet_file(
            tmp_path,
            f'targets:\n  - {{name: t, endpoint: "{nonconformant_endpoint}", gate: must, '
            "waivers_from: vendor.toml}\n",
        )
    )
    [result] = scan_fleet(fleet, policy(tmp_path), env={})
    assert result.status == "pass"


def test_the_rollup_counts_every_state(
    conformant_endpoint: str, nonconformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    fleet = load_fleet(
        fleet_file(
            tmp_path,
            f"""
targets:
  - {{name: a, endpoint: "{conformant_endpoint}", gate: must}}
  - {{name: b, endpoint: "{nonconformant_endpoint}", gate: must}}
  - {{name: c, endpoint: "http://127.0.0.1:9/mcp", gate: must, timeout: 1}}
""",
        )
    )
    summary = rollup(scan_fleet(fleet, policy(tmp_path), env={}))
    assert summary.to_json()["totals"] == {"pass": 1, "fail": 1, "error": 1}
    assert "| b | must | ❌ fail" in summary.to_markdown()
    text = summary.to_text()
    assert "ERROR c" in text and "unreachable" in text


def test_cli_writes_one_report_per_target_plus_a_rollup(
    conformant_endpoint: str, nonconformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    fleet = fleet_file(
        tmp_path,
        f"""
targets:
  - {{name: good, endpoint: "{conformant_endpoint}", gate: must}}
  - {{name: bad, endpoint: "{nonconformant_endpoint}", gate: must}}
""",
    )
    out = tmp_path / "out"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli",
            "scan",
            "--targets",
            str(fleet),
            "--out-dir",
            str(out),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
        env={**os.environ},
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert (out / "good.json").exists() and (out / "bad.json").exists()
    rolled = json.loads((out / "rollup.json").read_text())
    assert {t["name"]: t["status"] for t in rolled["targets"]} == {"good": "pass", "bad": "fail"}
    assert (out / "rollup.md").read_text().startswith("| Target")
