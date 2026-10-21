"""The Python harness and the Go fleet service, end to end.

The service reads what the harness writes, in a different language in a different
directory. This builds the real server binary, publishes with the real CLI, and reads
the result back over HTTP, so a rename on either side fails here and not in production.
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

from sentinel.publish import publish

pytestmark = pytest.mark.unit

ROOT = pathlib.Path(__file__).resolve().parents[2]
GO = shutil.which("go") or "/usr/local/go/bin/go"
INGEST = "ingest-token-for-tests"
READ = "read-token-for-tests"

needs_go = pytest.mark.skipif(
    not pathlib.Path(GO).exists(), reason="the Go toolchain is not installed"
)


@pytest.fixture(scope="module")
def service(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    binary = tmp_path_factory.mktemp("fleet") / "sentinel-server"
    built = subprocess.run(
        [GO, "build", "-o", str(binary), "./fleet/cmd/sentinel-server"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr
    port = free_port()
    proc = subprocess.Popen(
        [str(binary), "serve"],
        env={
            **os.environ,
            "SENTINEL_SERVER_ADDR": f"127.0.0.1:{port}",
            "SENTINEL_SERVER_INGEST_TOKEN": INGEST,
            "SENTINEL_SERVER_READ_TOKEN": READ,
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            if httpx.get(f"{base}/healthz", timeout=1).status_code == 200:
                break
        except httpx.RequestError:
            time.sleep(0.1)
    else:
        proc.kill()
        raise RuntimeError("the fleet service never became ready")
    yield base
    proc.terminate()
    proc.wait(timeout=10)


def sentinel(*args: str, token: str | None = INGEST) -> subprocess.CompletedProcess[str]:
    env = {**os.environ}
    if token is not None:
        env["SENTINEL_PUBLISH_TOKEN"] = token
    return subprocess.run(
        [sys.executable, "-m", "sentinel.cli", *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
        env=env,
    )


def api(base: str, path: str) -> dict:
    response = httpx.get(base + path, headers={"Authorization": f"Bearer {READ}"}, timeout=5)
    assert response.status_code == 200, (path, response.status_code, response.text)
    return response.json()


@needs_go
def test_the_server_refuses_to_start_without_an_ingest_token(tmp_path: pathlib.Path) -> None:
    binary = tmp_path / "sentinel-server"
    subprocess.run(
        [GO, "build", "-o", str(binary), "./fleet/cmd/sentinel-server"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("SENTINEL_SERVER_")}
    result = subprocess.run(
        [str(binary), "serve"], env=env, capture_output=True, text=True, timeout=10, check=False
    )
    assert result.returncode == 2
    assert "INGEST_TOKEN is required" in result.stderr


@needs_go
def test_a_published_scan_appears_with_its_verdict(
    service: str, conformant_endpoint: str, nonconformant_endpoint: str
) -> None:
    good = sentinel(
        "scan",
        "--endpoint",
        conformant_endpoint,
        "--gate",
        "must",
        "--target-name",
        "good-server",
        "--publish",
        service,
    )
    bad = sentinel(
        "scan",
        "--endpoint",
        nonconformant_endpoint,
        "--gate",
        "must",
        "--target-name",
        "bad-server",
        "--publish",
        service,
    )
    assert good.returncode == 0, good.stdout[-500:] + good.stderr
    assert bad.returncode == 1
    assert "published to" in good.stderr and "published to" in bad.stderr

    rows = {r["name"]: r for r in api(service, "/api/v1/targets")["targets"]}
    assert rows["good-server"]["status"] == "passing"
    assert rows["bad-server"]["status"] == "failing"
    assert rows["bad-server"]["failing"] > 20
    assert rows["good-server"]["failing"] == 0
    assert len(rows["good-server"]["manifestHash"]) == 64


@needs_go
def test_the_fleet_summary_and_posture_read_what_was_published(service: str) -> None:
    summary = api(service, "/api/v1/fleet/summary")
    assert summary["summary"]["targets"] >= 2
    assert summary["mostFailing"], "the failing target's rules should be ranked"
    posture = api(service, "/api/v1/targets/bad-server/posture?window=7d")
    assert posture["open"], "the failing findings are open"
    assert posture["daily"] and posture["daily"][-1]["failing"] > 20


@needs_go
def test_a_baselined_scan_publishes_its_failures_as_accepted(
    service: str, nonconformant_endpoint: str, tmp_path: pathlib.Path
) -> None:
    baseline = tmp_path / "b.json"
    assert (
        sentinel(
            "baseline",
            "create",
            "--endpoint",
            nonconformant_endpoint,
            "--out",
            str(baseline),
            "--target-name",
            "accepted-server",
        ).returncode
        == 0
    )
    ran = sentinel(
        "scan",
        "--endpoint",
        nonconformant_endpoint,
        "--gate",
        "must",
        "--baseline",
        str(baseline),
        "--target-name",
        "accepted-server",
        "--publish",
        service,
    )
    assert ran.returncode == 0
    row = next(
        r for r in api(service, "/api/v1/targets")["targets"] if r["name"] == "accepted-server"
    )
    assert row["failing"] == 0 and row["accepted"] > 20
    assert row["status"] == "passing", "accepted failures do not fail the gate"


@needs_go
def test_the_dashboard_serves_html_behind_the_read_token(service: str) -> None:
    assert httpx.get(service + "/", timeout=5).status_code == 401
    page = httpx.get(service + "/", auth=("anyone", READ), timeout=5)
    assert page.status_code == 200
    assert "bad-server" in page.text and "<svg" not in page.text
    detail = httpx.get(service + "/targets/name:bad-server", auth=("anyone", READ), timeout=5)
    assert detail.status_code == 200 and "<svg" in detail.text
    assert "default-src 'none'" in page.headers["content-security-policy"]


@needs_go
def test_a_wrong_token_is_a_warning_and_never_changes_the_exit_code(
    service: str, conformant_endpoint: str, nonconformant_endpoint: str
) -> None:
    good = sentinel(
        "scan",
        "--endpoint",
        conformant_endpoint,
        "--gate",
        "must",
        "--publish",
        service,
        token="wrong",
    )
    bad = sentinel(
        "scan",
        "--endpoint",
        nonconformant_endpoint,
        "--gate",
        "must",
        "--publish",
        service,
        token="wrong",
    )
    assert good.returncode == 0 and bad.returncode == 1
    assert "WARNING" in good.stderr and "HTTP 401" in good.stderr


def test_a_dead_service_is_a_warning_and_never_changes_the_exit_code(
    conformant_endpoint: str, nonconformant_endpoint: str
) -> None:
    dead = "http://127.0.0.1:9"
    good = sentinel("scan", "--endpoint", conformant_endpoint, "--gate", "must", "--publish", dead)
    bad = sentinel(
        "scan", "--endpoint", nonconformant_endpoint, "--gate", "must", "--publish", dead
    )
    assert good.returncode == 0, "a clean scan must not turn red because the service is down"
    assert bad.returncode == 1, "a failing scan must not turn green because the service is down"
    assert "WARNING could not reach" in good.stderr


def test_publish_reports_instead_of_raising() -> None:
    outcome = publish("http://127.0.0.1:9", {"schemaVersion": 2}, token="x", timeout=1)
    assert not outcome.ok and "could not reach" in outcome.detail


def test_the_report_carries_every_key_the_service_reads() -> None:
    """The contract, from the harness's side. The Go parser reads exactly these."""
    golden = json.loads((ROOT / "fleet/internal/model/testdata/report-v2.json").read_text())
    for key in (
        "schemaVersion",
        "startedAt",
        "specRevision",
        "target",
        "gate",
        "findings",
        "policy",
    ):
        assert key in golden, key
    for key in ("identity", "endpoint", "name", "manifestHash"):
        assert key in golden["target"], key
    assert {"selected", "failed"} <= set(golden["gate"])
    finding = golden["findings"][0]
    for key in ("ruleId", "severity", "outcome", "detail", "fingerprint", "waivedBy", "baselined"):
        assert key in finding, key
    assert all(
        {"rule", "reason", "expiresAt", "approvedBy"} <= set(w) for w in golden["policy"]["waivers"]
    )
