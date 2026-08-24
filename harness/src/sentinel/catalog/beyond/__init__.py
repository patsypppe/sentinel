"""Rules this project believes in that the specification does not require.

They live in their own `SENTINEL/` namespace and carry a `rationale` instead of
a `citation`, because a citation field pointing at nothing is how a catalog
starts lying. No spec gate ever considers them: `--gate must` and
`--gate should` filter to the MCP namespace, so a style opinion can never be
mistaken for a conformance failure.
"""

from __future__ import annotations

from sentinel.catalog.beyond import style

__all__ = ["style"]
