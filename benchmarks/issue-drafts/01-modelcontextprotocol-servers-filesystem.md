# Draft issue for github.com/modelcontextprotocol/servers

**Before posting:** search the repo's issues and PRs for "describe" / "excludePatterns" in case this
is already tracked. Post it from your own account; it is written in your voice.

**Title:** filesystem: five tool parameters have no description in the schema

**Body:**

Hi, and thanks for maintaining this server.

I'm building [Sentinel](https://github.com/patsypppe/sentinel), a linter for MCP servers, and
ran it on `@modelcontextprotocol/server-filesystem` 2.0.0 (also checked against the source at
`51b6382`). Most parameters carry a `.describe()`, but five do not, and a client or model reading the
tool schema gets no explanation for them:

| Tool | Parameter | Source |
|---|---|---|
| `directory_tree` | `excludePatterns` | `src/filesystem/server.ts` ~L110 |
| `search_files` | `pattern`, `excludePatterns` | ~L120-121 |
| `move_file` | `source`, `destination` | ~L114-115 |

The ones that are not self-evident are `excludePatterns` and `pattern`. From `lib.ts`, both are
matched with `minimatch(relativePath, pattern, { dot: true })` against the path *relative to the
search root*, which is not guessable from the name (glob vs regex, relative vs absolute). A suggested wording:

```ts
excludePatterns: z.array(z.string()).optional().default([])
  .describe("Glob patterns (minimatch, dotfiles included) matched against paths relative to `path`; matching entries are skipped."),
pattern: z.string()
  .describe("Glob pattern (minimatch, dotfiles included) matched against paths relative to `path`, e.g. '**/*.ts'."),
source: z.string().describe("Path of the file or directory to move. Must be inside an allowed directory."),
destination: z.string().describe("Destination path. Must be inside an allowed directory; the move fails if it already exists."),
```

(Please check the last sentence against the actual behaviour before adopting it; I only verified the
glob semantics.) Why it matters: two 2026 studies of MCP tool descriptions
([arXiv 2602.14878](https://arxiv.org/abs/2602.14878), [2602.18914](https://arxiv.org/abs/2602.18914))
found missing parameter semantics are common and change which tool an LLM selects.

Reproduce: `uvx --from "git+https://github.com/patsypppe/sentinel@main#subdirectory=harness" sentinel lint --command "npx -y @modelcontextprotocol/server-filesystem /tmp"`

Happy to send a PR with the descriptions if that's welcome.
