"""The MUST rule catalog.

Importing this package registers every MUST rule. Modules are grouped by the
capability they constrain, which is how the specification is organised and how a
reader looking for "the rules about headers" will look for them.
"""

from __future__ import annotations

from sentinel.catalog.must import (
    capabilities,
    discovery,
    envelope,
    headers,
    http,
    meta,
    mrtr,
    schemas,
    unverifiable,
)

__all__ = [
    "capabilities",
    "discovery",
    "envelope",
    "headers",
    "http",
    "meta",
    "mrtr",
    "schemas",
    "unverifiable",
]
