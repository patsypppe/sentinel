"""Snapshot and diff: detect a server changing under you.

`sentinel snapshot` records what a server advertises. `sentinel diff` compares a
live server to that record and classifies every difference, because not all drift
is an attack and a tool that reports every change as one gets muted.

The case this exists for is the **rug pull**: an MCP server you depend on and do
not control rewrites a tool's description after you approved it. A tool
description is text an LLM is steered by, so changing it changes what your agent
does without changing a single type signature. That is the one class of change a
schema-diff tool would miss, and here it is the most severe.

Severity, per class:

    DESCRIPTION_CHANGED   high   the text a model is steered by changed
    SCOPES_WIDENED        high   a tool now claims more authority
    ANNOTATIONS_WEAKENED  high   a read-only / non-destructive promise was dropped
    SCHEMA_WIDENED        warn   a required argument became optional, an enum grew
    SCHEMA_NARROWED       warn   a required argument was added, an enum shrank
    SCHEMA_CHANGED        warn   something else about the input contract moved
    TOOL_REMOVED          warn   a tool you may call is gone
    CAPABILITY_CHANGED    warn   what the server advertises about itself flipped
    TOOL_ADDED            info   a new tool appeared
    SCOPES_NARROWED       info
    SERVER_INFO_CHANGED   info
"""

from __future__ import annotations

import datetime
import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from sentinel import SPEC_REVISION, __version__
from sentinel.fingerprint import target_identity
from sentinel.probe.client import Probe
from sentinel.waivers import ConfigError

__all__ = [
    "Change",
    "ChangeKind",
    "Level",
    "Snapshot",
    "canonical_hash",
    "capture",
    "diff",
    "extract_scopes",
    "load",
    "save",
]

SCHEMA_VERSION = 1
MAX_PAGES = 50

#: Keys under which a tool advertises the scopes it needs, wherever it nests them.
_SCOPE_KEYS = frozenset({"scopes", "requiredscopes", "required_scopes", "scope"})


class Level(StrEnum):
    HIGH = "high"
    WARN = "warn"
    INFO = "info"


class ChangeKind(StrEnum):
    TOOL_ADDED = "TOOL_ADDED"
    TOOL_REMOVED = "TOOL_REMOVED"
    SCHEMA_WIDENED = "SCHEMA_WIDENED"
    SCHEMA_NARROWED = "SCHEMA_NARROWED"
    SCHEMA_CHANGED = "SCHEMA_CHANGED"
    DESCRIPTION_CHANGED = "DESCRIPTION_CHANGED"
    SCOPES_WIDENED = "SCOPES_WIDENED"
    SCOPES_NARROWED = "SCOPES_NARROWED"
    ANNOTATIONS_WEAKENED = "ANNOTATIONS_WEAKENED"
    CAPABILITY_CHANGED = "CAPABILITY_CHANGED"
    SERVER_INFO_CHANGED = "SERVER_INFO_CHANGED"


LEVELS: dict[ChangeKind, Level] = {
    ChangeKind.DESCRIPTION_CHANGED: Level.HIGH,
    ChangeKind.SCOPES_WIDENED: Level.HIGH,
    ChangeKind.ANNOTATIONS_WEAKENED: Level.HIGH,
    ChangeKind.SCHEMA_WIDENED: Level.WARN,
    ChangeKind.SCHEMA_NARROWED: Level.WARN,
    ChangeKind.SCHEMA_CHANGED: Level.WARN,
    ChangeKind.TOOL_REMOVED: Level.WARN,
    ChangeKind.CAPABILITY_CHANGED: Level.WARN,
    ChangeKind.TOOL_ADDED: Level.INFO,
    ChangeKind.SCOPES_NARROWED: Level.INFO,
    ChangeKind.SERVER_INFO_CHANGED: Level.INFO,
}


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def canonical_hash(value: Any) -> str:
    """SHA-256 of a JSON value in canonical form: sorted keys, no whitespace."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode()).hexdigest()


@dataclass(slots=True)
class Snapshot:
    endpoint: str
    spec_revision: str
    captured_at: str
    server_info: dict[str, Any] = field(default_factory=dict)
    capabilities: dict[str, Any] = field(default_factory=dict)
    #: name -> the tool exactly as advertised.
    tools: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def manifest_hash(self) -> str:
        """One hash for the whole tool manifest, order-independent."""
        return canonical_hash([self.tools[name] for name in sorted(self.tools)])

    def tool_hash(self, name: str) -> str:
        return canonical_hash(self.tools[name])


@dataclass(frozen=True, slots=True)
class Change:
    kind: ChangeKind
    tool: str
    detail: str
    before: str = ""
    after: str = ""

    @property
    def level(self) -> Level:
        return LEVELS[self.kind]


def extract_scopes(tool: dict[str, Any]) -> set[str]:
    """Every scope a tool claims, wherever the server chose to put them."""
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key).lower() in _SCOPE_KEYS:
                    if isinstance(value, str):
                        found.update(part for part in value.replace(",", " ").split() if part)
                    elif isinstance(value, list):
                        found.update(str(v) for v in value if isinstance(v, str))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for key in ("_meta", "annotations", "securitySchemes", "security"):
        walk(tool.get(key))
    walk({k: v for k, v in tool.items() if k in {"scopes", "requiredScopes"}})
    return found


def fetch_tools(probe: Probe) -> tuple[dict[str, dict[str, Any]] | None, str]:
    """Every tool the server lists, following pagination. (tools, why-not)."""
    tools: dict[str, dict[str, Any]] = {}
    cursor: str | None = None
    for _ in range(MAX_PAGES):
        response = (
            probe.tools_list() if cursor is None else probe.call("tools/list", {"cursor": cursor})
        )
        if not response.reached_server:
            return None, f"the server was unreachable: {response.transport_error}"
        result = response.result()
        if result is None:
            return None, "tools/list did not return a result"
        listed = result.get("tools")
        if not isinstance(listed, list):
            return None, "tools/list result has no tools array"
        for tool in listed:
            if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                tools[tool["name"]] = tool
        cursor = result.get("nextCursor") if isinstance(result.get("nextCursor"), str) else None
        if cursor is None:
            return tools, ""
    return None, f"tools/list still paginating after {MAX_PAGES} pages"


def capture(probe: Probe) -> Snapshot:
    """Record what the server advertises right now."""
    tools, why = fetch_tools(probe)
    if tools is None:
        raise ConfigError(f"cannot snapshot {probe.endpoint}: {why}")
    info: dict[str, Any] = {}
    capabilities: dict[str, Any] = {}
    discovered = probe.discover()
    result = discovered.result() if discovered.reached_server else None
    if result is not None:
        info = _as_dict(result.get("serverInfo"))
        capabilities = _as_dict(result.get("capabilities"))
    return Snapshot(
        endpoint=target_identity(probe.endpoint),
        spec_revision=SPEC_REVISION,
        captured_at=datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        server_info=info,
        capabilities=capabilities,
        tools=tools,
    )


def save(snapshot: Snapshot, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schemaVersion": SCHEMA_VERSION,
        "tool": "sentinel",
        "sentinelVersion": __version__,
        "specRevision": snapshot.spec_revision,
        "capturedAt": snapshot.captured_at,
        "endpoint": snapshot.endpoint,
        "manifestHash": snapshot.manifest_hash,
        "serverInfo": snapshot.server_info,
        "capabilities": snapshot.capabilities,
        "tools": [
            {"hash": snapshot.tool_hash(name), "tool": snapshot.tools[name]}
            for name in sorted(snapshot.tools)
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def load(path: Path) -> Snapshot:
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"snapshot {path} cannot be read: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schemaVersion") != SCHEMA_VERSION:
        raise ConfigError(f"snapshot {path} is not a schemaVersion {SCHEMA_VERSION} snapshot")
    tools: dict[str, dict[str, Any]] = {}
    for entry in raw.get("tools", []):
        tool = entry.get("tool") if isinstance(entry, dict) else None
        if isinstance(tool, dict) and isinstance(tool.get("name"), str):
            tools[tool["name"]] = tool
    snap = Snapshot(
        endpoint=str(raw.get("endpoint", "")),
        spec_revision=str(raw.get("specRevision", "")),
        captured_at=str(raw.get("capturedAt", "")),
        server_info=_as_dict(raw.get("serverInfo")),
        capabilities=_as_dict(raw.get("capabilities")),
        tools=tools,
    )
    recorded = raw.get("manifestHash")
    if recorded and recorded != snap.manifest_hash:
        raise ConfigError(
            f"snapshot {path} has been edited: its manifestHash does not match its tools. "
            "A snapshot is a record of what a server said; recreate it rather than editing it."
        )
    return snap


# --------------------------------------------------------------------------- diff


def _descriptions(schema: Any, path: str = "") -> dict[str, str]:
    """Every `description` string in a schema, keyed by where it sits."""
    found: dict[str, str] = {}
    if isinstance(schema, dict):
        for key, value in schema.items():
            here = f"{path}/{key}"
            if key == "description" and isinstance(value, str):
                found[here] = value
            else:
                found.update(_descriptions(value, here))
    elif isinstance(schema, list):
        for index, item in enumerate(schema):
            found.update(_descriptions(item, f"{path}[{index}]"))
    return found


def _required(schema: Any) -> set[str]:
    req = schema.get("required") if isinstance(schema, dict) else None
    return {r for r in req if isinstance(r, str)} if isinstance(req, list) else set()


def _properties(schema: Any) -> dict[str, Any]:
    props = schema.get("properties") if isinstance(schema, dict) else None
    return props if isinstance(props, dict) else {}


def _enum(schema: Any) -> set[str] | None:
    values = schema.get("enum") if isinstance(schema, dict) else None
    return {json.dumps(v, sort_keys=True) for v in values} if isinstance(values, list) else None


def _strip_descriptions(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: _strip_descriptions(v) for k, v in node.items() if k != "description"}
    if isinstance(node, list):
        return [_strip_descriptions(v) for v in node]
    return node


def _schema_changes(name: str, before: Any, after: Any) -> list[Change]:
    changes: list[Change] = []
    widened: list[str] = []
    narrowed: list[str] = []

    for arg in sorted(_required(before) - _required(after)):
        widened.append(f"argument {arg!r} is no longer required")
    for arg in sorted(_required(after) - _required(before)):
        narrowed.append(f"argument {arg!r} is now required")

    before_props, after_props = _properties(before), _properties(after)
    for arg in sorted(set(after_props) - set(before_props)):
        (narrowed if arg in _required(after) else widened).append(f"argument {arg!r} was added")
    for arg in sorted(set(before_props) - set(after_props)):
        narrowed.append(f"argument {arg!r} was removed")
    for arg in sorted(set(before_props) & set(after_props)):
        old_enum, new_enum = _enum(before_props[arg]), _enum(after_props[arg])
        if old_enum is not None and new_enum is not None:
            if new_enum - old_enum:
                widened.append(f"argument {arg!r} accepts more values")
            if old_enum - new_enum:
                narrowed.append(f"argument {arg!r} accepts fewer values")

    if widened:
        changes.append(Change(ChangeKind.SCHEMA_WIDENED, name, "; ".join(widened)))
    if narrowed:
        changes.append(Change(ChangeKind.SCHEMA_NARROWED, name, "; ".join(narrowed)))
    if not widened and not narrowed and _strip_descriptions(before) != _strip_descriptions(after):
        changes.append(
            Change(ChangeKind.SCHEMA_CHANGED, name, "the input schema changed in a way "
                   "that is neither a widening nor a narrowing (types or constraints)")
        )
    return changes


def _weakened(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    old = _as_dict(before.get("annotations"))
    new = _as_dict(after.get("annotations"))
    lost: list[str] = []
    if old.get("readOnlyHint") is True and new.get("readOnlyHint") is not True:
        lost.append("no longer annotated readOnlyHint=true")
    if old.get("destructiveHint") is False and new.get("destructiveHint") is not False:
        lost.append("no longer annotated destructiveHint=false")
    if old.get("openWorldHint") is False and new.get("openWorldHint") is not False:
        lost.append("no longer annotated openWorldHint=false")
    return lost


def _flatten(value: Any, prefix: str = "") -> dict[str, str]:
    if isinstance(value, dict):
        flat: dict[str, str] = {}
        for key, inner in value.items():
            flat.update(_flatten(inner, f"{prefix}.{key}" if prefix else str(key)))
        return flat or {prefix: "{}"}
    return {prefix: json.dumps(value, sort_keys=True)}


def diff(before: Snapshot, after: Snapshot) -> list[Change]:
    """Every difference between two snapshots, most severe first."""
    changes: list[Change] = []

    for name in sorted(set(after.tools) - set(before.tools)):
        changes.append(Change(ChangeKind.TOOL_ADDED, name, "a tool appeared"))
    for name in sorted(set(before.tools) - set(after.tools)):
        changes.append(Change(ChangeKind.TOOL_REMOVED, name, "a tool is no longer advertised"))

    for name in sorted(set(before.tools) & set(after.tools)):
        old, new = before.tools[name], after.tools[name]
        if canonical_hash(old) == canonical_hash(new):
            continue

        old_text = {"description": old.get("description", "")}
        new_text = {"description": new.get("description", "")}
        for where, text in _descriptions(old.get("inputSchema")).items():
            old_text[f"inputSchema{where}"] = text
        for where, text in _descriptions(new.get("inputSchema")).items():
            new_text[f"inputSchema{where}"] = text
        for where in sorted(set(old_text) | set(new_text)):
            if old_text.get(where) != new_text.get(where):
                changes.append(
                    Change(
                        ChangeKind.DESCRIPTION_CHANGED,
                        name,
                        f"the text at {where} changed. A model reads this text and "
                        "is steered by it.",
                        before=str(old_text.get(where, "")),
                        after=str(new_text.get(where, "")),
                    )
                )

        changes.extend(_schema_changes(name, old.get("inputSchema"), new.get("inputSchema")))

        gained = sorted(extract_scopes(new) - extract_scopes(old))
        lost_scopes = sorted(extract_scopes(old) - extract_scopes(new))
        if gained:
            changes.append(
                Change(ChangeKind.SCOPES_WIDENED, name, f"now claims scope(s): {', '.join(gained)}")
            )
        if lost_scopes:
            changes.append(
                Change(
                    ChangeKind.SCOPES_NARROWED, name, f"no longer claims: {', '.join(lost_scopes)}"
                )
            )

        for detail in _weakened(old, new):
            changes.append(Change(ChangeKind.ANNOTATIONS_WEAKENED, name, detail))

    old_caps, new_caps = _flatten(before.capabilities), _flatten(after.capabilities)
    for key in sorted(set(old_caps) | set(new_caps)):
        if old_caps.get(key) != new_caps.get(key):
            changes.append(
                Change(
                    ChangeKind.CAPABILITY_CHANGED,
                    "(server)",
                    f"capability {key or '(root)'} changed",
                    before=old_caps.get(key, "(absent)"),
                    after=new_caps.get(key, "(absent)"),
                )
            )

    if before.server_info != after.server_info:
        changes.append(
            Change(
                ChangeKind.SERVER_INFO_CHANGED,
                "(server)",
                "serverInfo changed",
                before=json.dumps(before.server_info, sort_keys=True),
                after=json.dumps(after.server_info, sort_keys=True),
            )
        )

    order = {Level.HIGH: 0, Level.WARN: 1, Level.INFO: 2}
    return sorted(changes, key=lambda c: (order[c.level], c.tool, c.kind.value))


def render_text(changes: list[Change], before: Snapshot, after: Snapshot) -> str:
    lines = [
        f"sentinel diff · {after.endpoint}",
        f"baseline: {before.captured_at}  manifest {before.manifest_hash[:12]}",
        f"live:     {after.captured_at}  manifest {after.manifest_hash[:12]}",
        "",
    ]
    if not changes:
        lines.append("no drift: the live manifest is identical to the snapshot")
        return "\n".join(lines) + "\n"
    high = [c for c in changes if c.level is Level.HIGH]
    lines.append(f"{len(changes)} change(s), {len(high)} high severity")
    lines.append("")
    for change in changes:
        lines.append(f"  [{change.level.value.upper():4}] {change.kind.value}  {change.tool}")
        lines.append(f"         {change.detail}")
        if change.before or change.after:
            lines.append(f"         before: {change.before[:160]}")
            lines.append(f"         after:  {change.after[:160]}")
    return "\n".join(lines) + "\n"


def render_json(changes: list[Change], before: Snapshot, after: Snapshot) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "endpoint": after.endpoint,
        "baselineManifestHash": before.manifest_hash,
        "liveManifestHash": after.manifest_hash,
        "highSeverity": sum(1 for c in changes if c.level is Level.HIGH),
        "changes": [
            {
                "kind": c.kind.value,
                "level": c.level.value,
                "tool": c.tool,
                "detail": c.detail,
                "before": c.before,
                "after": c.after,
            }
            for c in changes
        ],
    }
