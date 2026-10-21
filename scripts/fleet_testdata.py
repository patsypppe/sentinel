"""Regenerate the golden reports the fleet service's parser is tested against.

The Go service reads what the Python harness writes, and the two are in different
languages in different directories, so a rename on one side would break the other
silently. These files are the contract: `tests/harness/test_fleet_contract.py` fails
if the harness stops producing the keys the service reads, and the service's tests
parse these exact bytes.

    uv run python scripts/fleet_testdata.py
"""

from __future__ import annotations

import datetime
import json
import pathlib
import socket
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "fixtures")]

from sentinel import baseline as baseline_mod  # noqa: E402
from sentinel.config import load_policy  # noqa: E402
from sentinel.report import render_report  # noqa: E402
from sentinel.runner import ScanOptions, scan_target  # noqa: E402
from server.common import serve_background  # noqa: E402
from server.nonconformant import BEHAVIOUR, dispatch  # noqa: E402

OUT = ROOT / "fleet" / "internal" / "model" / "testdata"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def main() -> int:
    port = free_port()
    httpd, _ = serve_background(dispatch, port, banner="golden", **BEHAVIOUR)
    time.sleep(0.3)
    endpoint = f"http://127.0.0.1:{port}/mcp"
    try:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = pathlib.Path(tmp) / "sentinel.toml"
            cfg.write_text("")
            plain = load_policy(config=cfg, env={})
            first = scan_target(
                ScanOptions(endpoint=endpoint, policy=plain, target_name="broker-prod")
            )
            failing = [f for f in first.findings if f.outcome.value == "fail"]
            waived_rule = next(f.rule.id for f in failing if "/MUST/" in f.rule.id)
            expires = (datetime.date.today() + datetime.timedelta(days=20)).isoformat()
            cfg.write_text(
                f'[[waivers]]\nrule = "{waived_rule}"\n'
                'reason = "accepted during the migration window, PLAT-4412"\n'
                f'approved_by = "security@example.com"\nexpires_at = {expires}\n'
            )
            policy = load_policy(config=cfg, env={})
            taken = baseline_mod.create(first)
            # Baseline all but two, so the golden has failing, waived AND baselined findings.
            for fingerprint in list(taken.entries)[:2]:
                del taken.entries[fingerprint]
            report = scan_target(
                ScanOptions(
                    endpoint=endpoint, policy=policy, target_name="broker-prod", baseline=taken
                )
            )
        gate = {
            "selected": "must",
            "failed": report.gate(__import__("sentinel.runner", fromlist=["x"]).parse_gate("must"))
            == 1,
        }
        document = json.loads(
            render_report("json", report, gate="must", gate_failed=gate["failed"])
        )
    finally:
        httpd.shutdown()
        httpd.server_close()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "report-v2.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT / 'report-v2.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
