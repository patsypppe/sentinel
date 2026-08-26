"""Rules this project believes in that the specification does not require.

They live in their own `SENTINEL/` namespace and carry a `rationale` instead of
a `citation`, because a citation field pointing at nothing is how a catalog
starts lying. No spec gate ever considers them: `--gate must` and
`--gate should` filter to the MCP namespace, so a style opinion can never be
mistaken for a conformance failure. They are gateable on their own terms --
`--gate ops` considers `SENTINEL/OPS/*` and nothing else -- so a team that wants
an operational budget enforced can have one without either verdict borrowing the
other's authority.
"""

from __future__ import annotations

from sentinel.catalog.beyond import budget, style

__all__ = ["budget", "style"]
