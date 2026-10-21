"""A fleet of MCP servers, each with its own credential and its own gate.

In practice every MCP endpoint has its own token, its own tenant and its own
acceptable gate: you hold your own broker to `must`, and a vendor you do not
control to `should`. So a target is a named, separately credentialed connection,
not a bare URL.

    # sentinel-fleet.yaml
    concurrency: 5
    targets:
      - name: broker-prod
        endpoint: https://broker.acme.com/mcp
        token_env: BROKER_PROD_TOKEN
        gate: must
      - name: vendor-x
        endpoint: https://vendor-x.example/mcp
        token_env: VENDOR_X_TOKEN
        gate: should
        waivers_from: vendor-x.toml

Exit codes: `1` if **any** target fails **its own** gate, otherwise `2` if any
target could not be scanned, otherwise `0`. A target that is unreachable is a
harness error for that target only, and is never silently a pass: a fleet
dashboard that turns green because a server was down is worse than no dashboard.
"""

from __future__ import annotations

import dataclasses
import json
import os
import tomllib
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.config import Policy, waivers_from
from sentinel.grade import EXIT_GATE_FAILED, EXIT_HARNESS_ERROR, EXIT_OK, ScanReport
from sentinel.probe.client import Probe
from sentinel.runner import ScanOptions, parse_gate, scan_target
from sentinel.waivers import ConfigError

__all__ = ["Fleet", "Target", "TargetResult", "load_fleet", "rollup", "scan_fleet"]

_TARGET_KEYS = {"name", "endpoint", "token_env", "gate", "waivers_from", "safe", "timeout"}


@dataclass(frozen=True, slots=True)
class Target:
    name: str
    endpoint: str
    token_env: str | None = None
    gate: str | None = None
    waivers_from: Path | None = None
    safe: bool | None = None
    timeout: float | None = None


@dataclass(frozen=True, slots=True)
class Fleet:
    targets: tuple[Target, ...]
    concurrency: int = 5


@dataclass(slots=True)
class TargetResult:
    target: Target
    report: ScanReport | None = None
    exit_code: int = EXIT_OK
    error: str = ""
    gate: str = ""

    @property
    def status(self) -> str:
        if self.error:
            return "error"
        return "fail" if self.exit_code == EXIT_GATE_FAILED else "pass"


def _read(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text()
    except OSError as exc:
        raise ConfigError(f"fleet file {path} cannot be read: {exc}") from exc
    if path.suffix == ".toml":
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path}: not valid TOML: {exc}") from exc
    import yaml

    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: not valid YAML: {exc}") from exc
    return loaded if isinstance(loaded, dict) else {}


def load_fleet(path: Path) -> Fleet:
    raw = _read(path)
    listed = raw.get("targets")
    if not isinstance(listed, list) or not listed:
        raise ConfigError(f"{path}: needs a non-empty `targets` list")
    concurrency = raw.get("concurrency", 5)
    if not isinstance(concurrency, int) or concurrency < 1:
        raise ConfigError(f"{path}: concurrency must be an integer of at least 1")

    targets: list[Target] = []
    seen: set[str] = set()
    for index, item in enumerate(listed):
        where = f"{path}: targets[{index}]"
        if not isinstance(item, dict):
            raise ConfigError(f"{where} must be a mapping")
        unknown = set(item) - _TARGET_KEYS
        if unknown:
            raise ConfigError(f"{where}: unknown key(s) {sorted(unknown)}")
        for required in ("name", "endpoint"):
            if not item.get(required):
                raise ConfigError(f"{where}: missing {required!r}")
        name = str(item["name"])
        if name in seen:
            raise ConfigError(f"{where}: duplicate target name {name!r}")
        seen.add(name)
        if item.get("gate") is not None:
            parse_gate(str(item["gate"]))
        waiver_path = item.get("waivers_from")
        targets.append(
            Target(
                name=name,
                endpoint=str(item["endpoint"]),
                token_env=None if item.get("token_env") is None else str(item["token_env"]),
                gate=None if item.get("gate") is None else str(item["gate"]).lower(),
                waivers_from=None if waiver_path is None else (path.parent / str(waiver_path)),
                safe=None if item.get("safe") is None else bool(item["safe"]),
                timeout=None if item.get("timeout") is None else float(item["timeout"]),
            )
        )
    return Fleet(targets=tuple(targets), concurrency=concurrency)


def _scan_one(
    target: Target,
    base: Policy,
    env: Mapping[str, str],
    options: Callable[[Target], dict[str, Any]],
) -> TargetResult:
    result = TargetResult(target=target)
    try:
        token: str | None = None
        if target.token_env is not None:
            token = env.get(target.token_env)
            if not token:
                raise ConfigError(
                    f"environment variable {target.token_env} (token_env for {target.name}) "
                    "is not set. A target that needs a credential is not scanned without it, "
                    "because an unauthenticated scan would grade a login page."
                )
        gate_text = target.gate or base.gate
        severity = parse_gate(gate_text)
        result.gate = gate_text or "(none)"
        waivers = base.waivers
        if target.waivers_from is not None:
            waivers = (*waivers, *waivers_from(target.waivers_from))
        policy = dataclasses.replace(
            base,
            endpoint=target.endpoint,
            gate=gate_text,
            safe=base.safe if target.safe is None else target.safe,
            timeout=base.timeout if target.timeout is None else target.timeout,
            waivers=waivers,
        )
        extra = options(target)
        # Preflight. A target that does not answer is an error for that target,
        # and never a report full of INDETERMINATE that reads like a pass.
        with Probe(
            target.endpoint,
            timeout=policy.timeout,
            bearer_token=token,
            verify=extra.get("verify", True),
        ) as probe:
            reply = probe.discover()
            if not reply.reached_server:
                raise ConfigError(f"{target.endpoint} was unreachable: {reply.transport_error}")
        report = scan_target(
            ScanOptions(
                endpoint=target.endpoint,
                policy=policy,
                token=token,
                target_name=target.name,
                **extra,
            )
        )
        result.report = report
        result.exit_code = report.gate(severity)
    except Exception as exc:
        result.error = str(exc)
        result.exit_code = EXIT_HARNESS_ERROR
    return result


def scan_fleet(
    fleet: Fleet,
    base: Policy,
    *,
    env: Mapping[str, str] | None = None,
    options: Callable[[Target], dict[str, Any]] | None = None,
    concurrency: int | None = None,
) -> list[TargetResult]:
    """Scan every target, up to `concurrency` at once, in declaration order."""
    environment = os.environ if env is None else env
    per_target = options if options is not None else (lambda _t: {})
    workers = max(1, concurrency or fleet.concurrency)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda t: _scan_one(t, base, environment, per_target), fleet.targets))


def exit_code(results: list[TargetResult]) -> int:
    if any(r.status == "fail" for r in results):
        return EXIT_GATE_FAILED
    if any(r.status == "error" for r in results):
        return EXIT_HARNESS_ERROR
    return EXIT_OK


@dataclass(slots=True)
class Rollup:
    results: list[TargetResult] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        rows = []
        for r in self.results:
            report = r.report
            rows.append(
                {
                    "name": r.target.name,
                    "endpoint": r.target.endpoint,
                    "status": r.status,
                    "gate": r.gate,
                    "error": r.error,
                    "failing": 0
                    if report is None
                    else sum(1 for f in report.by_outcome_fail() if not f.suppressed),
                    "accepted": 0
                    if report is None
                    else sum(1 for f in report.by_outcome_fail() if f.suppressed),
                    "indeterminate": 0 if report is None else len(report.indeterminate),
                    "manifestHash": None if report is None else report.manifest_hash,
                }
            )
        return {
            "schemaVersion": 1,
            "targets": rows,
            "totals": {
                "pass": sum(1 for r in self.results if r.status == "pass"),
                "fail": sum(1 for r in self.results if r.status == "fail"),
                "error": sum(1 for r in self.results if r.status == "error"),
            },
        }

    def to_markdown(self) -> str:
        icon = {"pass": "✅", "fail": "❌", "error": "⚠️"}
        lines = [
            "| Target | Gate | Status | Failing | Accepted | Indeterminate |",
            "|---|---|---|---|---|---|",
        ]
        for row in self.to_json()["targets"]:
            note = f" — {row['error']}" if row["error"] else ""
            lines.append(
                f"| {row['name']} | {row['gate']} | {icon[row['status']]} {row['status']}{note} "
                f"| {row['failing']} | {row['accepted']} | {row['indeterminate']} |"
            )
        totals = self.to_json()["totals"]
        lines.append("")
        lines.append(
            f"**{totals['pass']} pass · {totals['fail']} fail · {totals['error']} error** "
            f"across {len(self.results)} target(s)"
        )
        return "\n".join(lines) + "\n"

    def to_text(self) -> str:
        lines = []
        for row in self.to_json()["targets"]:
            tail = f"  ({row['error']})" if row["error"] else ""
            lines.append(
                f"{row['status'].upper():5} {row['name']:<24} gate={row['gate']:<9} "
                f"failing={row['failing']} accepted={row['accepted']}{tail}"
            )
        totals = self.to_json()["totals"]
        lines.append(
            f"{totals['pass']} pass, {totals['fail']} fail, {totals['error']} error "
            f"across {len(self.results)} target(s)"
        )
        return "\n".join(lines) + "\n"


def rollup(results: list[TargetResult]) -> Rollup:
    return Rollup(results)


def write_reports(
    results: list[TargetResult],
    out_dir: Path,
    fmt: str,
    render: Callable[[str, ScanReport], str],
    extension: str,
) -> list[Path]:
    """One report per scanned target, named for the target, plus `rollup.json`."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for result in results:
        if result.report is None:
            continue
        path = out_dir / f"{result.target.name}.{extension}"
        path.write_text(render(fmt, result.report))
        written.append(path)
    summary = out_dir / "rollup.json"
    summary.write_text(json.dumps(Rollup(results).to_json(), indent=2) + "\n")
    (out_dir / "rollup.md").write_text(Rollup(results).to_markdown())
    return [*written, summary]
