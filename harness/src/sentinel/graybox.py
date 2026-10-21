"""Gray-box evidence: discharging `INDETERMINATE` with something the operator knows.

Five MUSTs cannot be settled from the wire. For each, the README says what evidence
would settle it, and this module is how that evidence is supplied:

    token-audience-validated                  a token for another audience
    handle-possession-is-not-authentication   a second principal's token
    no-token-passthrough                      a capture of the server's outbound traffic
    mrtr-retries-are-idempotent               a counter for the effect, read at its source
    invocations-are-audited                   a command that verifies the audit log

Absence of evidence never becomes a pass. A rule with no evidence behaves exactly as
it always did and returns INDETERMINATE; a rule with evidence returns a verdict that
names the evidence in `verified_by`, so a reader can check the claim instead of
trusting it.

Commands. Gray-box evidence can mean running an operator-supplied command, so:

* commands come from the configuration file only; no value a scanned server returns
  ever reaches a command line;
* they run with `shell=False`, as an argv list, with a timeout and a minimal
  environment;
* a command given as a single string is rejected, because the only way to run one
  is through a shell;
* `--no-exec` disables every command-shaped kind and leaves the token-shaped ones.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from sentinel.waivers import ConfigError

__all__ = [
    "COMMAND_TIMEOUT_S",
    "KINDS",
    "CommandResult",
    "Evidence",
    "run_command",
    "validate_graybox",
]

COMMAND_TIMEOUT_S = 15.0

#: What each kind needs from the `[graybox]` table.
#: kind -> (tokens by env-key, commands, extra required keys)
KINDS: dict[str, dict[str, tuple[str, ...]]] = {
    "wrong_audience_token": {"tokens": ("wrong_audience_token_env",), "commands": (), "keys": ()},
    "second_principal": {
        "tokens": ("second_principal_token_env",),
        "commands": (),
        "keys": ("handle",),
    },
    "egress_capture": {
        "tokens": ("egress_token_env",),
        "commands": ("egress_capture",),
        "keys": ("egress_tool",),
    },
    "effect_counter": {"tokens": (), "commands": ("effect_counter",), "keys": ("mrtr",)},
    "audit_verify": {"tokens": (), "commands": ("audit_verify",), "keys": ("audit_tool",)},
}

_ALL_KEYS = {key for spec in KINDS.values() for group in spec.values() for key in group} | {
    "audit_arguments",
    "egress_arguments",
}


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def run_command(argv: list[str], *, timeout: float = COMMAND_TIMEOUT_S) -> CommandResult:
    """Run an operator-supplied argv. Never through a shell."""
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
            # A minimal environment, so a command cannot read the scanner's other
            # secrets by accident. PATH is kept so an installed tool is found.
            env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")},
        )
    except subprocess.TimeoutExpired:
        return CommandResult(tuple(argv), -1, "", f"timed out after {timeout:.0f}s", True)
    except OSError as exc:
        return CommandResult(tuple(argv), -1, "", f"could not run: {exc}")
    return CommandResult(tuple(argv), proc.returncode, proc.stdout, proc.stderr)


def validate_graybox(table: Mapping[str, Any]) -> None:
    """Reject a `[graybox]` table that cannot be right, at load time."""
    unknown = set(table) - _ALL_KEYS
    if unknown:
        raise ConfigError(
            f"[graybox] has unknown key(s) {sorted(unknown)}; known: {sorted(_ALL_KEYS)}"
        )
    for key in ("egress_capture", "effect_counter", "audit_verify"):
        value = table.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            raise ConfigError(
                f"[graybox] {key} is a string. Give it as an argv list, for example "
                f'["psql", "-tAc", "select 1"]: a single string could only be run through '
                "a shell, and the scanner never starts one."
            )
        if not isinstance(value, list) or not value or not all(isinstance(a, str) for a in value):
            raise ConfigError(f"[graybox] {key} must be a non-empty list of strings")


@dataclass(slots=True)
class Evidence:
    """What the operator supplied, and the means to read it."""

    config: Mapping[str, Any] = field(default_factory=dict)
    env: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    allow_exec: bool = True

    def token(self, env_key: str) -> str | None:
        name = self.config.get(env_key)
        if not isinstance(name, str):
            return None
        return self.env.get(name) or None

    def command(self, key: str) -> list[str] | None:
        value = self.config.get(key)
        return [str(a) for a in value] if isinstance(value, list) and value else None

    def section(self, key: str) -> dict[str, Any]:
        value = self.config.get(key)
        return dict(value) if isinstance(value, dict) else {}

    def run(self, key: str) -> CommandResult:
        argv = self.command(key)
        if argv is None:
            raise ConfigError(f"[graybox] {key} is not configured")
        if not self.allow_exec:
            raise PermissionError("commands are disabled by --no-exec")
        return run_command(argv)

    def status(self, kind: str) -> tuple[str, str]:
        """("ready" | "absent" | "incomplete", why).

        `absent` means the operator supplied nothing for this kind and the rule
        should behave as it always did. `incomplete` means they started and did not
        finish, which is worth saying out loud: a typo in an environment variable
        name must not look the same as not having opted in.
        """
        spec = KINDS[kind]
        configured = [
            *(k for k in spec["tokens"] if k in self.config),
            *(k for k in spec["commands"] if k in self.config),
            *(k for k in spec["keys"] if k in self.config),
        ]
        if not configured:
            return "absent", ""
        problems: list[str] = []
        for key in spec["tokens"]:
            if key not in self.config:
                problems.append(f"[graybox] {key} is not set")
            elif self.token(key) is None:
                problems.append(
                    f"[graybox] {key} names the environment variable {self.config[key]!r}, "
                    "which is not set"
                )
        for key in spec["commands"]:
            if key not in self.config:
                problems.append(f"[graybox] {key} is not set")
            elif not self.allow_exec:
                problems.append(f"{key} is a command and --no-exec is in effect")
        problems.extend(f"[graybox] {k} is not set" for k in spec["keys"] if k not in self.config)
        if problems:
            return "incomplete", "; ".join(problems)
        return "ready", ""

    def has(self, kind: str) -> bool:
        return self.status(kind)[0] == "ready"
