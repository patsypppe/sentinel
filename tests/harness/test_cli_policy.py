"""The CLI honours the policy it resolves: file, env, flag, and refusals."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def sentinel(*args: str, cwd: pathlib.Path = REPO_ROOT, env: dict[str, str] | None = None):
    merged = {**os.environ, **(env or {})}
    return subprocess.run(
        [sys.executable, "-m", "sentinel.cli", *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd,
        env=merged,
    )


def test_the_endpoint_and_gate_can_come_from_the_config_file(
    nonconformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    (tmp_path / "sentinel.toml").write_text(
        f'[scan]\nendpoint = "{nonconformant_endpoint}"\ngate = "must"\n'
    )
    result = sentinel("scan", "--no-color", cwd=tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr


def test_the_endpoint_can_come_from_the_environment(
    conformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    result = sentinel(
        "scan",
        "--gate",
        "must",
        "--no-color",
        cwd=tmp_path,
        env={"SENTINEL_ENDPOINT": conformant_endpoint},
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_missing_endpoint_is_a_harness_error(tmp_path: pathlib.Path) -> None:
    result = sentinel("scan", cwd=tmp_path, env={"SENTINEL_ENDPOINT": ""})
    assert result.returncode == 2
    assert "no endpoint" in result.stderr


def test_a_malformed_waiver_date_is_exit_two_and_names_the_problem(
    conformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    (tmp_path / "sentinel.toml").write_text(
        '[[waivers]]\nrule = "MCP/2026-07-28/MUST/discover-implemented"\n'
        'reason = "an operator typo must not become permanent"\nexpires_at = "someday"\n'
    )
    result = sentinel("scan", "--endpoint", conformant_endpoint, cwd=tmp_path)
    assert result.returncode == 2
    assert "not a date" in result.stderr


def test_a_waiver_turns_a_red_gate_green_only_while_it_lasts(
    nonconformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    probe = sentinel("scan", "--endpoint", nonconformant_endpoint, "--format", "json", "--no-color")
    rules = [
        f["ruleId"]
        for f in json.loads(probe.stdout)["findings"]
        if f["outcome"] == "fail" and "/MUST/" in f["ruleId"]
    ]
    assert rules
    waivers = "".join(
        f'[[waivers]]\nrule = "{r}"\nreason = "accepted during the migration window"\n'
        "expires_at = 2099-01-01\n"
        for r in rules
    )
    (tmp_path / "sentinel.toml").write_text(waivers)
    green = sentinel("scan", "--endpoint", nonconformant_endpoint, "--gate", "must", cwd=tmp_path)
    assert green.returncode == 0, green.stdout[-800:] + green.stderr

    (tmp_path / "sentinel.toml").write_text(waivers.replace("2099-01-01", "2020-01-01"))
    red = sentinel("scan", "--endpoint", nonconformant_endpoint, "--gate", "must", cwd=tmp_path)
    assert red.returncode == 1


def test_baseline_create_then_scan_gates_clean_and_prune_drops_nothing_still_failing(
    nonconformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    path = tmp_path / "b.json"
    made = sentinel("baseline", "create", "--endpoint", nonconformant_endpoint, "--out", str(path))
    assert made.returncode == 0, made.stderr
    assert json.loads(path.read_text())["findings"]
    gated = sentinel(
        "scan", "--endpoint", nonconformant_endpoint, "--baseline", str(path), "--gate", "must"
    )
    assert gated.returncode == 0, gated.stdout[-600:]
    pruned = sentinel("baseline", "prune", str(path), "--endpoint", nonconformant_endpoint)
    assert pruned.returncode == 0
    assert "pruned 0 fixed" in pruned.stdout


@pytest.mark.parametrize("fmt", ["markdown", "junit", "html", "sarif", "json", "text"])
def test_every_format_works_through_the_cli(
    conformant_endpoint: str, tmp_path: pathlib.Path, fmt: str
) -> None:
    out = tmp_path / f"report.{fmt}"
    result = sentinel("scan", "--endpoint", conformant_endpoint, "--format", fmt, "--out", str(out))
    assert result.returncode == 0, result.stderr
    assert out.read_text().strip()


def test_an_unknown_format_is_a_harness_error(conformant_endpoint: str) -> None:
    result = sentinel("scan", "--endpoint", conformant_endpoint, "--format", "pdf")
    assert result.returncode == 2
