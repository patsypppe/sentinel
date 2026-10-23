# Benchmark: published MCP servers, linted

29 servers attempted, **27 started and listed tools** (2 did not: they need real credentials or a runtime this machine lacks).
Across those 27 servers: **335 tools, 1184 parameters**.

| Finding | Servers affected | Detail |
|---|---|---|
| Parameters with no description | **10 of 27** | 332 of 1184 parameters (28%) |
| Stub or missing tool description | **0 of 27** | 0 tools have no description at all |
| Tool list not in a stable order | 0 of 27 | |
| Illegal characters in a tool name | 0 of 27 | |
| Hidden characters or instruction-override text in a description | 0 of 27 | |
| Description mentions a credential path (`.env`, `.aws`) | 2 of 27 | usually benign, e.g. a warning |

## Per server

| Server | Tools | Params described | Rules failed |
|---|---|---|---|
| server-memory | 9 | 4/8 | parameters-are-described, tools-sorted-by-name |
| server-filesystem | 14 | 7/25 | parameters-are-described, tools-sorted-by-name |
| server-everything | 13 | 15/16 | parameters-are-described, tools-sorted-by-name |
| server-sequential-thinking | 1 | 9/9 | none |
| server-puppeteer | 7 | 15/15 | tools-sorted-by-name |
| server-github | 26 | 79/130 | parameters-are-described, tools-sorted-by-name |
| server-brave-search | 2 | 5/5 | tools-sorted-by-name |
| server-slack | 8 | 17/17 | tools-sorted-by-name |
| server-google-maps | 7 | 14/14 | tools-sorted-by-name |
| playwright-mcp | 25 | 70/70 | tools-sorted-by-name |
| context7 | 2 | 5/5 | tools-sorted-by-name |
| notion | 24 | 40/71 | parameters-are-described, tools-sorted-by-name |
| firecrawl | 28 | 55/194 | parameters-are-described, tools-sorted-by-name |
| chrome-devtools | 32 | 121/121 | none |
| desktop-commander | 25 | 0/72 | parameters-are-described, tool-description-injection, tools-sorted-by-name |
| tavily | 5 | 42/42 | tools-sorted-by-name |
| exa | 2 | 4/4 | tools-sorted-by-name |
| figma-developer | 2 | 7/7 | tools-sorted-by-name |
| mcp-server-kubernetes | 23 | 146/152 | parameters-are-described, tools-sorted-by-name |
| browser-tools | 16 | 37/37 | tools-sorted-by-name |
| playwright-executeautomation | 33 | 82/82 | tools-sorted-by-name |
| mcp-server-fetch | 1 | 4/4 | none |
| mcp-server-git | - | - | no tools listed (did not start, or needs real credentials) |
| mcp-server-time | 2 | 4/4 | tools-sorted-by-name |
| markitdown | 1 | 0/1 | parameters-are-described |
| duckduckgo | 3 | 0/9 | parameters-are-described, tools-sorted-by-name |
| arxiv | 19 | 55/55 | tools-sorted-by-name |
| basic-memory | - | - | no tools listed (did not start, or needs real credentials) |
| aws-documentation | 5 | 15/15 | tool-description-injection, tools-sorted-by-name |
