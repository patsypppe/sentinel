# Benchmark: published MCP servers, linted

29 servers attempted, **28 started and listed tools** (1 did not start, or listed no tools, within the timeout on this machine).
Across those 28 servers: **362 tools, 1349 parameters**.

| Finding | Servers affected | Detail |
|---|---|---|
| Parameters documented nowhere (not in the schema, not in the description text) | **8 of 28** | 234 of 1349 parameters (17%) |
| Parameters documented only in the description text, not the schema | 3 of 28 | 59 of 1349 parameters |
| Self-evident plain-string parameters (`path`, `url`, ...) | | 37 of 1349 |
| Parameters documented in the schema | | 1019 of 1349 parameters |
| Stub or missing tool description | **0 of 28** | 0 tools have no description at all |
| Tool list not in a stable order | 0 of 28 | |
| Illegal characters in a tool name | 0 of 28 | |
| Hidden characters or instruction-override text in a description | 0 of 28 | |
| Description mentions a credential path (`.env`, `.aws`) | 2 of 28 | usually benign, e.g. a warning |

## Per server

| Server | Tools | In schema / text only / self-evident / nowhere | Rules failed |
|---|---|---|---|
| server-memory | 9 | 8 / 0 / 0 / 0 | tools-sorted-by-name |
| server-filesystem | 14 | 8 / 0 / 12 / 5 | parameters-are-described, tools-sorted-by-name |
| server-everything | 13 | 15 / 0 / 0 / 1 | parameters-are-described, tools-sorted-by-name |
| server-sequential-thinking | 1 | 9 / 0 / 0 / 0 | none |
| server-puppeteer | 7 | 15 / 0 / 0 / 0 | tools-sorted-by-name |
| server-github | 26 | 79 / 0 / 2 / 49 | parameters-are-described, tools-sorted-by-name |
| server-brave-search | 2 | 5 / 0 / 0 / 0 | tools-sorted-by-name |
| server-slack | 8 | 17 / 0 / 0 / 0 | tools-sorted-by-name |
| server-google-maps | 7 | 14 / 0 / 0 / 0 | tools-sorted-by-name |
| playwright-mcp | 25 | 70 / 0 / 0 / 0 | tools-sorted-by-name |
| context7 | 2 | 5 / 0 / 0 / 0 | tools-sorted-by-name |
| notion | 24 | 40 / 0 / 0 / 31 | parameters-are-described, tools-sorted-by-name |
| firecrawl | 28 | 55 / 24 / 13 / 102 | parameters-are-described, tools-sorted-by-name |
| chrome-devtools | 32 | 121 / 0 / 0 / 0 | none |
| desktop-commander | 25 | 0 / 26 / 8 / 38 | parameters-are-described, tool-description-injection, tools-sorted-by-name |
| tavily | 5 | 42 / 0 / 0 / 0 | tools-sorted-by-name |
| exa | 2 | 4 / 0 / 0 / 0 | tools-sorted-by-name |
| figma-developer | 2 | 7 / 0 / 0 / 0 | tools-sorted-by-name |
| mcp-server-kubernetes | 23 | 146 / 0 / 1 / 5 | parameters-are-described, tools-sorted-by-name |
| browser-tools | 16 | 37 / 0 / 0 / 0 | tools-sorted-by-name |
| playwright-executeautomation | 33 | 82 / 0 / 0 / 0 | tools-sorted-by-name |
| mcp-server-fetch | 1 | 4 / 0 / 0 / 0 | none |
| mcp-server-git | - | - | no tools listed (did not start, or listed none) |
| mcp-server-time | 2 | 4 / 0 / 0 / 0 | tools-sorted-by-name |
| markitdown | 1 | 0 / 0 / 1 / 0 | none |
| duckduckgo | 3 | 0 / 9 / 0 / 0 | tools-sorted-by-name |
| arxiv | 19 | 55 / 0 / 0 / 0 | tools-sorted-by-name |
| basic-memory | 27 | 162 / 0 / 0 / 3 | parameters-are-described, tools-sorted-by-name |
| aws-documentation | 5 | 15 / 0 / 0 / 0 | tool-description-injection, tools-sorted-by-name |
