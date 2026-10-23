# Draft issue for github.com/firecrawl/firecrawl-mcp-server

**Before posting:** search the repo's issues for existing "parameter descriptions" requests. Post it from
your own account. I did not read this server's source, only its published tool list, so the issue is
limited to what that shows.

**Title:** Tool input schemas: most parameters have no description (102 of 194 in v3.34.1)

**Body:**

Hi, thanks for the MCP server. I ran [Sentinel](https://github.com/patsypppe/sentinel), a linter for MCP
servers, on `firecrawl-mcp` 3.34.1 over stdio. Tool descriptions are detailed (they explain when to use
each tool), but in the `inputSchema` of the tools 102 of 194 parameters have no `description`, and they
are not documented in the tool description text either. A model choosing arguments from the schema sees only a name and a type.

The most ambiguous are numeric parameters, where units and bounds matter:
`waitFor`, `delay`, `timeout` (`firecrawl_interact`), `limit`, `maxDiscoveryDepth`, `maxConcurrency`
(`firecrawl_crawl`), and structured ones with no explanation of their fields: `jsonOptions`,
`queryOptions`, `screenshotOptions`, `pdfOptions` (`firecrawl_scrape`, `firecrawl_parse`) and
`body` (`firecrawl_monitor_update`).

Two 2026 studies of MCP tool descriptions
([arXiv 2602.14878](https://arxiv.org/abs/2602.14878), [2602.18914](https://arxiv.org/abs/2602.18914))
found missing parameter semantics are common and measurably change which tool and arguments an LLM picks.

Reproduce: `FIRECRAWL_API_KEY=x uvx --from "git+https://github.com/patsypppe/sentinel@main#subdirectory=harness" sentinel lint --command "npx -y firecrawl-mcp" --env FIRECRAWL_API_KEY=x`
(`tools/list` works with a dummy key; no request is made to your API.)

If the schemas are generated from Zod, adding `.describe()` to those fields would cover it. Happy to help.
