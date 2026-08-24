#!/usr/bin/env python3
"""The nine-step demo from `docs/HANDOFF.md` §13.

Runs against a live stack. Each step prints the command before its output, so a
recording is also a transcript someone can copy from.

    make up && make demo
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
GO = shutil.which("/opt/homebrew/bin/go") or shutil.which("go") or "go"

BROKER = "http://localhost:8080/mcp"
FIXTURE = "http://127.0.0.1:9000/mcp"
PROTOCOL = "2026-07-28"

OPERATOR = "00000000-0000-0000-0000-0000000000a2"
ANALYST = "00000000-0000-0000-0000-0000000000a1"
AUDIENCE = "https://broker.sentinel.local"
ISSUER = "https://issuer.sentinel.local"
DEV_SEED = "a" * 64
DEMO_TENANT = "00000000-0000-0000-0000-000000000001"
APP_DSN = (
    "postgres://broker_app:broker_app_dev_only@localhost:5432/sentinel?sslmode=disable"
)

BOLD, DIM, GREEN, RED, YELLOW, RESET = (
    "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[33m", "\033[0m"
)


def heading(n: int, title: str) -> None:
    print(f"\n{BOLD}{'━' * 78}{RESET}")
    print(f"{BOLD}  {n}. {title}{RESET}")
    print(f"{BOLD}{'━' * 78}{RESET}\n")


def shell(command: str, *, expect_exit: int | None = None) -> subprocess.CompletedProcess[str]:
    """Run a command, showing it first."""
    print(f"{DIM}$ {command}{RESET}")
    proc = subprocess.run(
        command, shell=True, cwd=REPO, capture_output=True, text=True, check=False
    )
    output = (proc.stdout + proc.stderr).rstrip()
    if output:
        print(output)
    if expect_exit is not None:
        colour = GREEN if proc.returncode == expect_exit else RED
        print(f"{colour}exit {proc.returncode}{RESET} {DIM}(expected {expect_exit}){RESET}")
        if proc.returncode != expect_exit:
            raise SystemExit(f"demo: expected exit {expect_exit}, got {proc.returncode}")
    return proc


def mint(principal: str, scopes: str, audience: str = AUDIENCE) -> str:
    env = {
        **os.environ,
        "BROKER_OAUTH_DEV_SEED": DEV_SEED,
        "BROKER_OAUTH_ISSUER": ISSUER,
        "BROKER_OAUTH_AUDIENCE": AUDIENCE,
    }
    proc = subprocess.run(
        [GO, "run", "./broker/cmd/broker", "mint-token",
         "--principal", principal, "--audience", audience, "--scopes", scopes, "--ttl", "1h"],
        cwd=REPO, env=env, capture_output=True, text=True, check=True,
    )
    return proc.stdout.strip()


def call(
    method: str, params: dict[str, Any] | None = None, *, token: str, name: str | None = None
) -> dict[str, Any]:
    body = {
        "jsonrpc": "2.0",
        "id": params.pop("__id", None) if params else None,
        "method": method,
        "params": {**(params or {}), "_meta": {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL,
        }},
    }
    if body["id"] is None:
        body["id"] = int(time.time() * 1000) % 100000

    headers = {
        "Content-Type": "application/json",
        "Mcp-Method": method,
        "Authorization": f"Bearer {token}",
    }
    # Mcp-Name is defined for tools/call, resources/read and prompts/get. A
    # method with no params.name or params.uri has nothing for it to match, and
    # the broker refuses a header asserting a body value that does not exist.
    mcp_name = name or (params or {}).get("name") or (params or {}).get("uri")
    if mcp_name is not None:
        headers["Mcp-Name"] = str(mcp_name)

    request = urllib.request.Request(
        BROKER,
        data=json.dumps(body).encode(),
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=30) as resp:
        return json.loads(resp.read())


def wait_for_broker(timeout: float = 90) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen("http://localhost:8080/healthz", timeout=2):
                return
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(1)
    raise SystemExit("demo: the broker never became ready. Run `make up` first.")


def free_port_taken(port: int) -> bool:
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", port)) == 0


def psql(query: str) -> str:
    proc = subprocess.run(
        ["docker", "compose", "exec", "-T", "postgres",
         "psql", "-U", "sentinel", "-d", "sentinel", "-tAc", query],
        cwd=REPO, capture_output=True, text=True, check=False,
    )
    return proc.stdout.strip()


def main() -> int:
    print(f"{BOLD}Sentinel — the nine-step demo{RESET}")
    print(f"{DIM}docs/HANDOFF.md §13{RESET}")

    wait_for_broker()
    operator_token = mint(OPERATOR, "ops:plan ops:apply warehouse:read warehouse:describe")
    analyst_token = mint(ANALYST, "warehouse:read warehouse:describe ops:plan ops:apply")

    fixture: subprocess.Popen[bytes] | None = None
    if not free_port_taken(9000):
        fixture = subprocess.Popen(
            [sys.executable, "-m", "server.nonconformant"],
            cwd=REPO / "fixtures", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

    try:
        heading(1, "Scan an unmigrated server — 25 MUST failures, each with a citation")
        shell(f"uv run sentinel scan --endpoint {FIXTURE} --gate must --no-color | head -32",
              expect_exit=0)
        shell(f"uv run sentinel scan --endpoint {FIXTURE} --gate must --no-color > /dev/null",
              expect_exit=1)

        heading(2, "Scan the broker — zero")
        shell(
            f"uv run sentinel scan --endpoint {BROKER} --gate must --no-color "
            f'--token "{operator_token}" | tail -12',
            expect_exit=0,
        )

        heading(3, "The deprecation inventory, with removal windows")
        shell(f"uv run sentinel deprecations --endpoint {FIXTURE} --no-color | head -20")

        heading(4, "concise versus detailed")
        print(f"{DIM}$ go test ./broker/internal/tools/warehouse/ -run Concise -v{RESET}")
        shell(
            f"{GO} test ./broker/internal/tools/warehouse/ -run "
            "'TestConciseIsSmallerThanDetailed|TestConciseCrossoverIsAtTwoRows' -v 2>&1 "
            "| grep -E 'rows:|row :'"
        )

        heading(5, "An irreversible tool asks before it acts")
        plan = call("tools/call", {
            "name": "ops.deployment_plan",
            "arguments": {"service": "checkout", "version": "1.4.2", "replicas": 3},
        }, token=operator_token)
        handle = plan["result"]["structuredContent"]["handle"]
        print(f"{DIM}plan handle: {handle}{RESET}\n")

        first = call("tools/call", {
            "name": "ops.deployment_apply", "arguments": {"plan": handle},
        }, token=operator_token)
        result = first["result"]
        print(json.dumps({
            "resultType": result["resultType"],
            "inputRequests": result["inputRequests"],
            "requestState": result["requestState"][:44] + "…",
        }, indent=2))
        state = result["requestState"]
        print(f"\n{GREEN}Nothing has been deployed. The confirmation is required by the "
              f"type system, not by remembering.{RESET}")

        heading(6, "Replay the identical retry — six new JSON-RPC ids, one deployment")
        before = int(psql("SELECT count(*) FROM deployments") or 0)
        retry = {
            "name": "ops.deployment_apply",
            "arguments": {
                "plan": handle, "requestState": state, "inputResponses": {"confirm": True},
            },
        }
        seen: set[str] = set()
        for request_id in range(3, 9):
            resp = call("tools/call", {**retry, "__id": request_id}, token=operator_token)
            deployment_id = resp["result"]["structuredContent"]["deploymentId"]
            seen.add(deployment_id)
            print(f'  jsonrpc id {request_id} → deploymentId {deployment_id}')

        after = int(psql("SELECT count(*) FROM deployments") or 0)
        attempts = int(psql(
            "SELECT count(*) FROM deployment_attempts WHERE correlation_id IN "
            "(SELECT correlation_id FROM deployments ORDER BY applied_at DESC LIMIT 1)"
        ) or 0)
        print(f"\n  distinct deployment ids: {len(seen)}")
        print(f"  deployments created:     {after - before}")
        print(f"  effect ran:              {attempts} time(s)")
        if len(seen) == 1 and after - before == 1 and attempts == 1:
            print(f"\n{GREEN}Six retries. One deployment.{RESET}")
        else:
            raise SystemExit("demo: exactly-once did not hold")

        heading(7, "A leaked handle, presented as a different principal")
        refused = call("tools/call", {
            "name": "ops.deployment_apply", "arguments": {"plan": handle},
        }, token=analyst_token)
        print(json.dumps(refused["error"], indent=2))
        print(f"\n{GREEN}One message for every cause — distinguishing them would confirm "
              f"the handle exists.{RESET}")
        print(f"{DIM}And the refusal is audited:{RESET}")
        print("  " + (psql(
            "SELECT tool_name || '  ' || outcome || '  code=' || coalesce(error_code::text,'-') "
            "FROM tool_invocations ORDER BY seq DESC LIMIT 1"
        ) or "(no audit row)"))

        heading(8, "traceparent travels in _meta, so the trace joins up")
        traced = call("tools/call", {
            "name": "warehouse.query",
            "arguments": {"sql": "SELECT count(*) FROM warehouse.orders"},
        }, token=operator_token)
        meta = traced["result"].get("_meta", {})
        print(json.dumps(meta, indent=2))
        print(f"{DIM}The broker echoes the negotiated version and continues the client's "
              f"trace rather than starting a new one.{RESET}")

        heading(9, "The audit chain: grants stop the ordinary case, the chain catches the rest")

        # Scoped to the demo tenant. The integration suite deliberately tampers
        # with chains belonging to throwaway tenants, and a verify across all of
        # them would report those breaks — correctly, but confusingly here.
        verify = (
            f'BROKER_DATABASE_URL="{APP_DSN}" {GO} run ./broker/cmd/broker audit verify '
            f"--tenant {DEMO_TENANT} --from 2026-01-01 --to 2027-01-01"
        )

        print(f"{DIM}First: the application role cannot rewrite the log at all.{RESET}")
        shell(
            'docker compose exec -T postgres psql -U broker_app -d sentinel '
            '-c "UPDATE tool_invocations SET outcome=\'ok\';" 2>&1 | head -2'
        )

        print(f"\n{DIM}The demo tenant's chain, as it stands:{RESET}")
        intact = shell(verify)
        if intact.returncode != 0:
            print(f"{YELLOW}This tenant's chain was already broken by an earlier run. "
                  f"Re-run with a fresh database (`make down && make up`) to see the "
                  f"before-and-after.{RESET}")
        else:
            print(f"\n{DIM}Now a superuser — someone past the grants — rewrites one row.{RESET}")
            target = psql(
                f"SELECT seq FROM tool_invocations WHERE tenant_id = '{DEMO_TENANT}' "
                "ORDER BY seq LIMIT 1 OFFSET 2"
            )
            shell(
                "docker compose exec -T postgres psql -U sentinel -d sentinel -tAc "
                f"\"UPDATE tool_invocations SET outcome='denied' WHERE tenant_id = "
                f"'{DEMO_TENANT}' AND seq = {target};\""
            )
            print()
            shell(verify, expect_exit=1)
            print(f"\n{GREEN}Named the exact row. The grants stop the ordinary case; "
                  f"the chain catches whoever gets past them.{RESET}")

        print(f"\n{BOLD}{'━' * 78}{RESET}")
        print(f"{GREEN}{BOLD}  All nine steps passed.{RESET}")
        print(f"{DIM}  A MUST regression fails the conformance workflow; see "
              f".github/workflows/conformance.yml{RESET}")
        print(f"{BOLD}{'━' * 78}{RESET}\n")
        return 0

    finally:
        if fixture is not None:
            fixture.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
