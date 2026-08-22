"""Bootstrap smoke tests: prove both language harnesses actually run."""

from __future__ import annotations

import subprocess
import sys

import pytest

pytestmark = pytest.mark.unit


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sentinel.cli", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_help_exits_zero() -> None:
    result = _run("--help")
    assert result.returncode == 0, result.stderr


def test_version_reports_the_spec_revision() -> None:
    result = _run("version")
    assert result.returncode == 0, result.stderr
    assert "2026-07-28" in result.stdout
