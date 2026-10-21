"""Classify the official MCP conformance suite's results against Sentinel's.

Usage:
    python compare.py <label> <official-output-dir> <official-run-log> <sentinel-scan.json>

Prints one JSON object per server. Every failing official check lands in exactly
one bucket, decided by the suite's own output rather than by judgement:

* ``unscored``  -- the scenario is marked ``(extension)`` or ``(pending)`` in the
  run log. The suite does not count these toward its exit code.
* ``fixture``   -- the failure message says the server lacks something the suite
  ships for its own reference server: a tool, prompt or resource it calls by
  name (``test_simple_text``, ``slow_compute``, ``test://static-text`` ...), or a
  check it marks "Not testable". A server that is correct but is not the
  reference server fails these by construction.
* ``core``      -- everything else: a scored failure the server could fix.

The ``fixture`` patterns and the FIXTURE_CHECKS list below are the whole of the
judgement in this script; a reader who disagrees with one can delete it and
re-run.
"""

from __future__ import annotations

import glob
import json
import os
import re
import sys
from collections import Counter

FIXTURE_PATTERNS = [
    r"no such tool '",
    r"Tool '?[\w.-]+'? not found",
    r"Not testable",
    r"resource not found: 'test://",
    r"unknown method 'prompts/get'",
    r"unknown method 'completion/complete'",
    r"Prerequisite failed",
    r"fixture from Check",
    r"no task was created",
]


#: Checks whose failure message does not name the reference-server fixture they
#: depend on. Each was confirmed by reading the suite's source for that check.
FIXTURE_CHECKS = {
    "sep-2322-multi-round-r1": "calls tools/call 'test_input_required_result_multi_round'",
}


def unscored_scenarios(run_log: str) -> set[str]:
    found: set[str] = set()
    with open(run_log, encoding="utf-8") as fh:
        lines = fh.readlines()
    for line in lines:
        match = re.search(r"[✓✗]\s+([\w.-]+)\s+\((extension|pending)\)", line)
        if match:
            found.add(match.group(1))
    return found


def official(out_dir: str, run_log: str) -> dict[str, object]:
    unscored = unscored_scenarios(run_log)
    statuses: Counter[str] = Counter()
    buckets: Counter[str] = Counter()
    core: list[dict[str, str]] = []
    for path in sorted(glob.glob(os.path.join(out_dir, "*", "checks.json"))):
        scenario = os.path.basename(os.path.dirname(path))
        scenario = re.sub(r"-\d{4}-\d{2}-\d{2}T.*$", "", scenario).removeprefix("server-")
        with open(path, encoding="utf-8") as fh:
            checks = json.load(fh)
        for check in checks:
            status = str(check.get("status"))
            statuses[status] += 1
            if status != "FAILURE":
                continue
            message = str(check.get("errorMessage") or "")
            if scenario in unscored:
                buckets["unscored"] += 1
            elif check.get("id") in FIXTURE_CHECKS or any(
                re.search(p, message) for p in FIXTURE_PATTERNS
            ):
                buckets["fixture"] += 1
            else:
                buckets["core"] += 1
                core.append(
                    {"scenario": scenario, "check": str(check.get("id")), "message": message}
                )
    return {
        "checks": sum(statuses.values()),
        "statuses": dict(statuses),
        "failures": dict(buckets),
        "coreFailures": core,
    }


def sentinel(scan_path: str) -> dict[str, object]:
    with open(scan_path, encoding="utf-8") as fh:
        report = json.load(fh)
    failing = [f for f in report["findings"] if f["outcome"] == "fail"]
    spec = [f for f in failing if f["namespace"] == "MCP"]
    return {
        "rules": len(report["findings"]),
        "mustFailures": sorted(f["ruleId"] for f in spec if f["severity"] == "must"),
        "shouldFailures": sorted(f["ruleId"] for f in spec if f["severity"] == "should"),
        "beyondSpecFailures": sorted(f["ruleId"] for f in failing if f["namespace"] != "MCP"),
        "indeterminate": report["summary"]["total"]["indeterminate"],
    }


def main() -> None:
    label, out_dir, run_log, scan = sys.argv[1:5]
    print(json.dumps({
        "server": label,
        "official": official(out_dir, run_log),
        "sentinel": sentinel(scan),
    }, indent=2))


if __name__ == "__main__":
    main()
