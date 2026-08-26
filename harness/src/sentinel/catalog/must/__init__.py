"""The MUST rule catalog.

Importing this package registers every MUST rule. Modules are grouped by the
capability they constrain, which is how the specification is organised and how a
reader looking for "the rules about headers" will look for them.
"""

from __future__ import annotations

from sentinel.catalog.must import discovery, envelope, headers, http, meta, unverifiable

__all__ = ["discovery", "envelope", "headers", "http", "meta", "unverifiable"]
