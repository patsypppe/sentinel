"""The Action, the GitLab template, the pre-commit hooks and the Dockerfile.

These are files nobody runs until a stranger does, so they are tested the way a
stranger would meet them: the Action's scan step is executed as the bash it is, and
every flag any template passes is checked against the real CLI.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = pathlib.Path(__file__).resolve().parents[2]


def load(path: str) -> Any:
    return yaml.safe_load((ROOT / path).read_text())


def scan_step() -> str:
    steps = load("action.yml")["runs"]["steps"]
    return next(s for s in steps if s.get("id") == "scan")["run"]


def run_action_scan(env: dict[str, str], tmp_path: pathlib.Path) -> tuple[int, str, pathlib.Path]:
    """Execute the Action's scan step with the inputs GitHub would put in env."""
    output = tmp_path / "output"
    summary = tmp_path / "summary"
    output.write_text("")
    summary.write_text("")
    bin_dir = str(pathlib.Path(sys.executable).parent)
    full = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_OUTPUT": str(output),
        "GITHUB_STEP_SUMMARY": str(summary),
        "SENTINEL_ACTION_SARIF": str(tmp_path / "out.sarif"),
        "SENTINEL_ACTION_ANCHOR": "README.md",
        "SENTINEL_ACTION_GATE": "must",
        "SENTINEL_ACTION_SAFE": "false",
        "SENTINEL_ACTION_NOEXEC": "false",
        **env,
    }
    proc = subprocess.run(
        ["bash", "-c", scan_step()],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
        env=full,
    )
    assert proc.returncode == 0, proc.stderr
    code = int(re.search(r"exit-code=(\d+)", output.read_text()).group(1))  # type: ignore[union-attr]
    return code, summary.read_text(), tmp_path / "out.sarif"


def test_the_action_passes_a_conformant_server_and_writes_both_reports(
    conformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    code, summary, sarif = run_action_scan(
        {"SENTINEL_ACTION_ENDPOINT": conformant_endpoint}, tmp_path
    )
    assert code == 0
    assert "**PASS**" in summary
    assert sarif.exists() and '"version": "2.1.0"' in sarif.read_text()


def test_the_action_fails_a_nonconformant_server_and_says_so_in_the_summary(
    nonconformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    code, summary, sarif = run_action_scan(
        {"SENTINEL_ACTION_ENDPOINT": nonconformant_endpoint}, tmp_path
    )
    assert code == 1
    assert "**FAIL**" in summary
    assert "#### ❌" in summary
    assert sarif.exists()


def test_the_action_reports_a_scanner_error_as_two_not_as_a_verdict(tmp_path: pathlib.Path) -> None:
    code, summary, _ = run_action_scan({"SENTINEL_ACTION_ENDPOINT": ""}, tmp_path)
    assert code == 2
    assert "could not run" in summary


def test_the_action_honours_a_baseline_and_a_config(
    nonconformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    baseline = tmp_path / "baseline.json"
    made = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli",
            "baseline",
            "create",
            "--endpoint",
            nonconformant_endpoint,
            "--out",
            str(baseline),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
    )
    assert made.returncode == 0, made.stderr
    code, _, _ = run_action_scan(
        {
            "SENTINEL_ACTION_ENDPOINT": nonconformant_endpoint,
            "SENTINEL_ACTION_BASELINE": str(baseline),
        },
        tmp_path,
    )
    assert code == 0, "everything failing was in the baseline, so nothing gates"


def test_the_action_scans_a_fleet(conformant_endpoint: str, tmp_path: pathlib.Path) -> None:
    fleet = tmp_path / "fleet.yaml"
    fleet.write_text(
        f'targets:\n  - {{name: only, endpoint: "{conformant_endpoint}", gate: must}}\n'
    )
    code, summary, _ = run_action_scan({"SENTINEL_ACTION_TARGETS": str(fleet)}, tmp_path)
    assert code == 0
    assert "fleet" in summary and "| only |" in summary


def cli_flags(command: str) -> set[str]:
    out = subprocess.run(
        [sys.executable, "-m", "sentinel.cli", *command.split(), "--help"],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
        env={**os.environ, "COLUMNS": "200", "NO_COLOR": "1"},
    ).stdout
    return set(re.findall(r"--[a-z][a-z0-9-]*", out))


def test_every_flag_the_action_passes_exists() -> None:
    used = set(re.findall(r"--[a-z][a-z0-9-]*", scan_step())) - {"--endpoint"}
    assert used <= cli_flags("scan") | {"--endpoint"}, used - cli_flags("scan")


def test_every_flag_the_gitlab_template_passes_exists() -> None:
    text = (ROOT / "ci/gitlab/sentinel.gitlab-ci.yml").read_text()
    jobs = yaml.safe_load(text)
    used: set[str] = set()
    for job in jobs.values():
        for line in job["script"]:
            used |= set(re.findall(r"--[a-z][a-z0-9-]*", line))
    assert used <= cli_flags("scan"), used - cli_flags("scan")


def test_the_precommit_hooks_are_well_formed_and_their_flags_exist() -> None:
    hooks = load(".pre-commit-hooks.yaml")
    assert {h["id"] for h in hooks} == {"sentinel-scan", "sentinel-scan-local"}
    for hook in hooks:
        assert hook["pass_filenames"] is False, "a scan is of a server, not of changed files"
        assert hook["language"] in {"docker_image", "system"}
        assert "pre-push" in hook["stages"], "a scan makes hundreds of requests"
        assert set(re.findall(r"--[a-z][a-z0-9-]*", hook["entry"])) <= cli_flags("scan")


def test_the_gitlab_junit_report_is_what_the_scan_writes() -> None:
    job = load("ci/gitlab/sentinel.gitlab-ci.yml")[".sentinel-scan"]
    assert job["artifacts"]["reports"]["junit"] == "sentinel-junit.xml"
    assert "--format junit --out sentinel-junit.xml" in " ".join(job["script"])
    assert job["artifacts"]["when"] == "always"


def test_the_dockerfile_runs_as_a_non_root_user_with_the_cli_as_entrypoint() -> None:
    text = (ROOT / "Dockerfile").read_text()
    assert re.search(r"^USER 10001$", text, re.MULTILINE)
    assert 'ENTRYPOINT ["sentinel"]' in text
    final = text.split("FROM python:3.12-slim")[-1]
    assert "pip install build" not in final, "the final stage must not carry the build tooling"
    assert (ROOT / ".dockerignore").read_text().count("broker/") == 1


def test_the_release_workflow_signs_and_ships_an_sbom_without_a_stored_key() -> None:
    workflow = load(".github/workflows/release.yml")
    jobs = workflow["jobs"]
    assert {"build", "publish", "image", "attest"} <= set(jobs)
    text = (ROOT / ".github/workflows/release.yml").read_text()
    assert "cosign sign --yes" in text and "cosign sign-blob --yes" in text
    assert "cyclonedx-json" in text
    assert "COSIGN_PRIVATE_KEY" not in text, "keyless signing means there is no key to leak"
    # Each job holds only the permissions it uses.
    assert jobs["publish"]["permissions"] == {"id-token": "write"}
    assert jobs["image"]["permissions"]["packages"] == "write"
    assert workflow["permissions"] == {"contents": "read"}
