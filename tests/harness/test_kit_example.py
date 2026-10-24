"""The Go server kit's example, built from source and graded by the harness.

A kit whose example can rot is a kit nobody trusts. This builds `mcp/example`,
serves it, and requires `sentinel scan --gate must` to exit 0 against it -- so a
change to the kit that makes the minimal server non-conformant turns the build red
rather than surprising the first stranger who copies it.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator

import httpx
import pytest
from tests.harness.conftest import free_port

pytestmark = pytest.mark.unit

ROOT = pathlib.Path(__file__).resolve().parents[2]
GO = shutil.which("go") or "/usr/local/go/bin/go"

# Locally a missing Go toolchain skips these tests. In CI, SENTINEL_REQUIRE_GO is set and
# they run, and fail loudly if Go is missing, rather than letting the claim they back
# quietly stop being checked.
needs_go = pytest.mark.skipif(
    not pathlib.Path(GO).exists() and not os.environ.get("SENTINEL_REQUIRE_GO"),
    reason="the Go toolchain is not installed",
)


@pytest.fixture(scope="module")
def example_endpoint(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    binary = tmp_path_factory.mktemp("kit") / "example"
    built = subprocess.run(
        [GO, "build", "-o", str(binary), "./mcp/example/cmd"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr
    port = free_port()
    proc = subprocess.Popen(
        [str(binary), "-addr", f"127.0.0.1:{port}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    endpoint = f"http://127.0.0.1:{port}"
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            if httpx.get(f"{endpoint}/healthz", timeout=1).status_code == 200:
                break
        except httpx.RequestError:
            time.sleep(0.1)
    else:
        proc.kill()
        raise RuntimeError("the example server never became ready")
    yield f"{endpoint}/mcp"
    proc.terminate()
    proc.wait(timeout=10)


def scan(endpoint: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sentinel.cli", "scan", "--endpoint", endpoint, "--no-color", *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
        env={**os.environ},
    )


@needs_go
def test_the_example_passes_the_must_gate(example_endpoint: str) -> None:
    result = scan(example_endpoint, "--gate", "must")
    assert result.returncode == 0, result.stdout[-3000:]
    assert "FAILING" not in result.stdout


@needs_go
def test_the_example_has_no_failure_of_any_severity(example_endpoint: str) -> None:
    report = json.loads(scan(example_endpoint, "--format", "json").stdout)
    failing = [f["ruleId"] for f in report["findings"] if f["outcome"] == "fail"]
    assert failing == [], failing


@needs_go
def test_the_example_passes_the_security_gate_too(example_endpoint: str) -> None:
    assert scan(example_endpoint, "--gate", "security").returncode == 0


@needs_go
def test_the_example_is_audited_and_says_what_it_cannot_prove(example_endpoint: str) -> None:
    report = json.loads(scan(example_endpoint, "--format", "json").stdout)
    indeterminate = {
        f["ruleId"].rsplit("/", 1)[-1]
        for f in report["findings"]
        if f["outcome"] == "indeterminate"
    }
    # The same five the harness cannot settle from the wire for any server, plus rate limiting,
    # which needs --probe-rate-limit to send the traffic.
    assert indeterminate == {
        "handle-possession-is-not-authentication",
        "mrtr-retries-are-idempotent",
        "no-token-passthrough",
        "token-audience-validated",
        "invocations-are-audited",
        "tool-invocations-rate-limited",
    }
