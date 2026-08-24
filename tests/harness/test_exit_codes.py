"""The exit-code contract.

`docs/HANDOFF.md` §8.8:

    "`sentinel scan --gate must` exits 1 if any MUST rule returns FAIL, and 0
    otherwise. INDETERMINATE never fails a gate but is always printed. Every
    other subcommand reserves non-zero for harness errors — CI must distinguish
    'the server is wrong' from 'the scanner broke'."

That last sentence is the one worth testing hardest. A scanner that returns 1
when it crashed makes every red build ambiguous, and a team learns to ignore it.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

from sentinel.grade import EXIT_GATE_FAILED, EXIT_HARNESS_ERROR, EXIT_OK

pytestmark = pytest.mark.unit

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def sentinel(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sentinel.cli", *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )


def test_the_three_codes_are_distinct() -> None:
    assert len({EXIT_OK, EXIT_GATE_FAILED, EXIT_HARNESS_ERROR}) == 3
    assert EXIT_OK == 0
    assert EXIT_GATE_FAILED == 1
    assert EXIT_HARNESS_ERROR == 2


def test_clean_scan_exits_zero(conformant_endpoint: str) -> None:
    result = sentinel("scan", "--endpoint", conformant_endpoint, "--gate", "must", "--no-color")
    assert result.returncode == EXIT_OK, result.stdout + result.stderr


def test_must_failure_exits_one(nonconformant_endpoint: str) -> None:
    result = sentinel("scan", "--endpoint", nonconformant_endpoint, "--gate", "must", "--no-color")
    assert result.returncode == EXIT_GATE_FAILED, result.stdout + result.stderr


def test_no_gate_never_fails(nonconformant_endpoint: str) -> None:
    """Without --gate, a scan REPORTS but does not judge.

    This is what makes `sentinel scan` usable for exploring a third-party server
    without the run going red.
    """
    result = sentinel("scan", "--endpoint", nonconformant_endpoint, "--no-color")
    assert result.returncode == EXIT_OK
    assert "FAIL" in result.stdout, "the failures must still be reported"


def test_indeterminate_does_not_fail_the_gate(conformant_endpoint: str) -> None:
    """The conformant fixture reports five INDETERMINATE MUSTs and still exits 0."""
    result = sentinel(
        "scan", "--endpoint", conformant_endpoint, "--gate", "must",
        "--format", "json",
    )
    assert result.returncode == EXIT_OK
    report = json.loads(result.stdout)
    assert report["summary"]["must"]["indeterminate"] > 0, (
        "this test is vacuous unless some rule reported INDETERMINATE"
    )


def test_a_harness_error_is_two_not_one() -> None:
    """The distinction CI depends on.

    An unparseable --gate is a mistake in how the tool was INVOKED. Reporting it
    as 1 would say the server failed conformance, which is a different and
    untrue thing.
    """
    result = sentinel("scan", "--endpoint", "http://127.0.0.1:1/mcp", "--gate", "nonsense")
    assert result.returncode == EXIT_HARNESS_ERROR, result.stdout + result.stderr
    assert result.returncode != EXIT_GATE_FAILED


def test_an_unknown_format_is_a_harness_error() -> None:
    # --retries 0: this scan is aimed at a closed port on purpose, and the
    # backoff for a whole catalog of doomed requests is time the suite spends
    # re-proving what --retries already has its own test for.
    result = sentinel(
        "scan", "--endpoint", "http://127.0.0.1:1/mcp", "--format", "yaml", "--retries", "0"
    )
    assert result.returncode == EXIT_HARNESS_ERROR


def test_an_unreachable_target_does_not_fail_the_gate() -> None:
    """An outage is not a conformance verdict.

    A scan against a server that is down must not report the server as
    non-conformant — the correct answer is that nothing could be determined.
    """
    result = sentinel(
        "scan", "--endpoint", "http://127.0.0.1:1/mcp", "--gate", "must",
        "--timeout", "1", "--no-color", "--retries", "0",
    )
    assert result.returncode != EXIT_GATE_FAILED, (
        "an unreachable server was reported as failing conformance"
    )


def test_catalog_validate_exits_zero() -> None:
    result = sentinel("catalog", "validate")
    assert result.returncode == EXIT_OK, result.stdout + result.stderr
    assert "UNVERIFIABLE" in result.stdout, (
        "catalog validate must name the rules it cannot verify; that list is the "
        "harness's own limitations section"
    )


def test_out_writes_the_file_and_still_summarises(
    conformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    """--out must not silence the terminal.

    A scan whose only output is a file nobody opens is a scan nobody reads.
    """
    target = tmp_path / "scan.json"
    result = sentinel(
        "scan", "--endpoint", conformant_endpoint, "--format", "json",
        "--out", str(target), "--no-color",
    )
    assert result.returncode == EXIT_OK
    assert target.exists()
    assert json.loads(target.read_text())["findings"]
    assert "MUST:" in result.stdout, "the summary must still reach the terminal"
