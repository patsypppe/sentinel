"""Sentinel — a conformance harness for MCP 2026-07-28.

The harness never imports broker internals and runs against any endpoint URL.
Its probe is a deliberately literal MCP client: requests are constructed by hand
from the specification, because an SDK that helpfully adds `Mcp-Method` would
make the rule requiring `Mcp-Method` untestable.
"""

__version__ = "0.2.0"

#: The MCP revision this harness grades against. Rule IDs embed it, so changing
#: it is a catalog-wide event, not a constant edit.
SPEC_REVISION = "2026-07-28"
