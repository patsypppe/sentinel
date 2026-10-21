"""Stable finding identity.

A baseline is only as good as the identity it stores. If a finding's identity
changes when nothing meaningful did, every scan re-raises everything it was told
to ignore and the baseline becomes a file nobody trusts. detect-secrets refuses to
fingerprint on line numbers for exactly this reason: "code is expected to move
around". Sentinel's equivalent hazards are request ids, timestamps and ephemeral
handles in evidence, so none of those are ever hashed.

    fingerprint = sha256(rule_id ‖ target_identity ‖ evidence_key)
"""

from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

__all__ = ["fingerprint", "target_identity"]

_DEFAULT_PORTS = {"http": 80, "https": 443}


def target_identity(endpoint: str, name: str | None = None) -> str:
    """Who a finding is about.

    A configured target name wins, because a fleet target keeps its identity when
    its URL moves. Otherwise the endpoint is normalised to scheme, host, port and
    path: credentials and query strings are stripped (a token in a URL must not
    leak into a baseline file that gets committed), the scheme and host are
    lower-cased, and a default port is dropped so `https://a/mcp` and
    `https://a:443/mcp` are the same target.
    """
    if name:
        return f"name:{name}"
    parts = urlsplit(endpoint.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    authority = host if port is None or port == _DEFAULT_PORTS.get(scheme) else f"{host}:{port}"
    path = parts.path.rstrip("/") or "/"
    return f"{scheme}://{authority}{path}"


def fingerprint(rule_id: str, target: str, *evidence_keys: str) -> str:
    """The identity of one rule failing on one target in one way."""
    material = "\x1f".join([rule_id, target, *evidence_keys])
    return hashlib.sha256(material.encode()).hexdigest()
