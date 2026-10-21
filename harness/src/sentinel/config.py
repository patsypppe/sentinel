"""`sentinel.toml`: policy, and exactly where each value of it came from.

Precedence, narrow to wide:

    CLI flag  >  SENTINEL_* environment variable  >  project file
              >  `extends` chain  >  built-in default

Every resolved value carries its source into the report's `policy` block, and the
precedence matrix is tested cell by cell. Trivy has open bugs where its own
documented precedence is not honoured; "documented intent" and "tested behaviour"
are different things.

Three rules in here are decisions, not conveniences:

* A severity override may only make a rule **stricter** or disable it. Promoting a
  SHOULD to a MUST is a policy a company is entitled to hold. Demoting a MUST to
  get a green gate is laundering, and the file is rejected. (Disabling is allowed
  because it is visible in the report.)
* A rule id that does not exist is an error everywhere it can be named. A typo in
  `disable` would otherwise silently disable nothing and look like success.
* Secrets never live in the file. A token is read from the environment variable
  the file *names*.
"""

from __future__ import annotations

import datetime
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.catalog.base import REGISTRY, Registry, Severity
from sentinel.probe.transport import DEFAULT_RETRIES
from sentinel.waivers import ConfigError, Waiver, parse_waiver

__all__ = ["DISCOVERY_NAMES", "ConfigError", "Policy", "discover", "load_policy"]

DISCOVERY_NAMES = ("sentinel.toml", ".sentinel.toml")

SOURCE_CLI = "cli"
SOURCE_ENV = "env"
SOURCE_DEFAULT = "default"

_STRICTNESS = {Severity.MAY: 0, Severity.SHOULD: 1, Severity.MUST: 2}

#: name -> (default, env var, parser)
_SETTINGS: dict[str, tuple[Any, str, Any]] = {}


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off", ""}:
        return False
    raise ValueError(f"{value!r} is not a boolean")


def _to_gate(value: Any) -> str | None:
    return None if value in (None, "") else str(value).lower()


_SETTINGS.update(
    {
        "endpoint": (None, "SENTINEL_ENDPOINT", lambda v: None if v in (None, "") else str(v)),
        "gate": (None, "SENTINEL_GATE", _to_gate),
        "timeout": (10.0, "SENTINEL_TIMEOUT", float),
        "concurrency": (8, "SENTINEL_CONCURRENCY", int),
        "retries": (DEFAULT_RETRIES, "SENTINEL_RETRIES", int),
        "safe": (False, "SENTINEL_SAFE", _to_bool),
        "include_deprecated": (False, "SENTINEL_INCLUDE_DEPRECATED", _to_bool),
        "token_env": ("SENTINEL_TOKEN", "SENTINEL_TOKEN_ENV", str),
    }
)

#: Where each setting lives in the file: (table, key).
_FILE_KEYS = {
    "endpoint": ("scan", "endpoint"),
    "gate": ("scan", "gate"),
    "timeout": ("scan", "timeout"),
    "concurrency": ("scan", "concurrency"),
    "retries": ("scan", "retries"),
    "safe": ("scan", "safe"),
    "token_env": ("scan", "token_env"),
    "include_deprecated": ("rules", "include_deprecated"),
}


@dataclass(slots=True)
class _Layer:
    path: Path | None
    label: str
    data: dict[str, Any]


@dataclass(slots=True)
class Policy:
    endpoint: str | None = None
    gate: str | None = None
    timeout: float = 10.0
    concurrency: int = 8
    retries: int = DEFAULT_RETRIES
    safe: bool = False
    include_deprecated: bool = False
    token_env: str = "SENTINEL_TOKEN"
    disabled: frozenset[str] = frozenset()
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    waivers: tuple[Waiver, ...] = ()
    graybox: dict[str, Any] = field(default_factory=dict)
    #: setting name -> "cli" | "env: NAME" | "default" | "<file>" | "extends: <file>"
    sources: dict[str, str] = field(default_factory=dict)
    config_path: Path | None = None

    def token(self, env: Mapping[str, str] | None = None) -> str | None:
        """The bearer token, read from the environment variable named by `token_env`."""
        environment = os.environ if env is None else env
        return environment.get(self.token_env) or None

    def describe(self) -> dict[str, Any]:
        """The `policy` block of a report: resolved values with their sources."""
        values: dict[str, Any] = {
            name: {"value": getattr(self, name), "source": self.sources.get(name, SOURCE_DEFAULT)}
            for name in _SETTINGS
            if name != "token_env"
        }
        return {
            "config": str(self.config_path) if self.config_path else None,
            "settings": values,
            "disabledRules": sorted(self.disabled),
            "severityOverrides": {k: v.value for k, v in sorted(self.severity_overrides.items())},
            "waivers": [
                {
                    "rule": w.rule,
                    "endpoint": w.endpoint,
                    "reason": w.reason,
                    "expiresAt": w.expires_at.isoformat(),
                    "approvedBy": w.approved_by,
                }
                for w in self.waivers
            ],
        }


def discover(explicit: Path | None, cwd: Path | None = None) -> Path | None:
    """`--config`, else `./sentinel.toml`, else `./.sentinel.toml`, else none."""
    if explicit is not None:
        if not explicit.is_file():
            raise ConfigError(f"--config {explicit} does not exist")
        return explicit
    base = cwd or Path.cwd()
    for name in DISCOVERY_NAMES:
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def _read(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: not valid TOML: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"{path}: cannot be read: {exc}") from exc


def _layers(path: Path) -> list[_Layer]:
    """The project file first, then everything it extends, nearest first."""
    layers: list[_Layer] = []
    seen: set[Path] = set()
    current: Path | None = path
    label = str(path)
    first = True
    while current is not None:
        resolved = current.resolve()
        if resolved in seen:
            raise ConfigError(f"{path}: `extends` forms a cycle at {current}")
        seen.add(resolved)
        data = _read(current)
        layers.append(_Layer(current, label if first else f"extends: {current}", data))
        parent = data.get("extends")
        if parent is None:
            break
        if not isinstance(parent, str):
            raise ConfigError(f"{current}: `extends` must be a path, not {parent!r}")
        target = Path(parent)
        if not target.is_absolute():
            target = current.parent / target
        if not target.is_file():
            raise ConfigError(
                f"{current}: extends {parent!r}, which does not exist at {target}. "
                "`extends` takes a path to another sentinel.toml."
            )
        current = target
        first = False
    return layers


def _file_value(layers: list[_Layer], table: str, key: str) -> tuple[Any, str] | None:
    for layer in layers:
        section = layer.data.get(table)
        if isinstance(section, dict) and key in section:
            return section[key], layer.label
    return None


def _check_rule_ids(registry: Registry, where: str, ids: list[str]) -> None:
    known = {r.id for r in registry.all(include_deprecated=True)}
    for rule_id in ids:
        if rule_id not in known:
            near = sorted(k for k in known if k.rsplit("/", 1)[-1] == rule_id.rsplit("/", 1)[-1])
            hint = f" Did you mean {near[0]}?" if near else ""
            raise ConfigError(f"{where}: {rule_id!r} is not a rule in this catalog.{hint}")


def load_policy(
    *,
    config: Path | None = None,
    cli: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
    registry: Registry | None = None,
    cwd: Path | None = None,
) -> Policy:
    """Resolve a policy from every source, with the documented precedence."""
    reg = registry if registry is not None else REGISTRY
    environment = os.environ if env is None else env
    cli_values = {k: v for k, v in (cli or {}).items() if v is not None}

    path = discover(config, cwd)
    layers = _layers(path) if path is not None else []
    policy = Policy(config_path=path)

    for name, (default, env_name, parse) in _SETTINGS.items():
        value: Any = default
        source = SOURCE_DEFAULT
        found = _file_value(layers, *_FILE_KEYS[name]) if name in _FILE_KEYS else None
        if found is not None:
            value, source = found
        if env_name in environment and environment[env_name] != "":
            value, source = environment[env_name], f"{SOURCE_ENV}: {env_name}"
        if name in cli_values:
            value, source = cli_values[name], SOURCE_CLI
        try:
            parsed = parse(value) if value is not None else None
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{name} = {value!r} (from {source}) is invalid: {exc}") from exc
        setattr(policy, name, parsed if parsed is not None or default is None else default)
        policy.sources[name] = source

    if policy.concurrency < 1:
        raise ConfigError(
            f"concurrency = {policy.concurrency} (from {policy.sources['concurrency']}) "
            "must be at least 1"
        )
    if policy.retries < 0:
        raise ConfigError(f"retries = {policy.retries} must be 0 or more")
    if policy.timeout <= 0:
        raise ConfigError(f"timeout = {policy.timeout} must be positive")

    disabled: set[str] = set()
    overrides: dict[str, Severity] = {}
    waivers: list[Waiver] = []
    graybox: dict[str, Any] = {}
    # Widest first, so a nearer layer overrides a farther one.
    for layer in reversed(layers):
        rules = layer.data.get("rules", {})
        if not isinstance(rules, dict):
            raise ConfigError(f"{layer.path}: [rules] must be a table")
        listed = rules.get("disable", [])
        if not isinstance(listed, list):
            raise ConfigError(f"{layer.path}: rules.disable must be a list of rule ids")
        _check_rule_ids(reg, f"{layer.path}: rules.disable", [str(i) for i in listed])
        disabled.update(str(i) for i in listed)

        severities = rules.get("severity", {})
        if not isinstance(severities, dict):
            raise ConfigError(f"{layer.path}: [rules.severity] must be a table")
        for rule_id, wanted in severities.items():
            _check_rule_ids(reg, f"{layer.path}: rules.severity", [rule_id])
            try:
                new = Severity(str(wanted).lower())
            except ValueError:
                raise ConfigError(
                    f"{layer.path}: rules.severity.{rule_id} = {wanted!r} is not one of "
                    "must, should, may"
                ) from None
            current = next(r for r in reg.all(include_deprecated=True) if r.id == rule_id).severity
            if _STRICTNESS[new] < _STRICTNESS[current]:
                raise ConfigError(
                    f"{layer.path}: rules.severity.{rule_id} = {new.value!r} would demote a "
                    f"{current.value.upper()} rule. A severity override may only make a rule "
                    "stricter. To stop a rule failing your gate, add it to rules.disable "
                    "(visible in the report) or write a waiver with an expiry."
                )
            overrides[rule_id] = new

        for index, raw in enumerate(layer.data.get("waivers", [])):
            if not isinstance(raw, dict):
                raise ConfigError(f"{layer.path}: waivers[{index}] must be a table")
            waiver = _parse_layer_waiver(raw, index, layer)
            _check_rule_ids(reg, f"{layer.path}: waivers[{index}]", [waiver.rule])
            waivers.append(waiver)

        gb = layer.data.get("graybox", {})
        if not isinstance(gb, dict):
            raise ConfigError(f"{layer.path}: [graybox] must be a table")
        graybox.update(gb)

    policy.disabled = frozenset(disabled)
    policy.severity_overrides = overrides
    policy.waivers = tuple(waivers)
    policy.graybox = graybox
    return policy


def _parse_layer_waiver(raw: dict[str, Any], index: int, layer: _Layer) -> Waiver:
    if "extends" in raw:
        raise ConfigError(
            f"{layer.path}: `extends` appears inside waivers[{index}]. In TOML a bare key "
            "belongs to the table above it, so `extends` must be the first line of the "
            "file, before any [table]."
        )
    return parse_waiver(raw, index)


def today() -> datetime.date:
    return datetime.datetime.now(datetime.UTC).date()
