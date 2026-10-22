# Benchmark: servers built with the official SDKs

## MCP Python SDK 2.x (MCPServer, streamable HTTP)

Protocol generation detected: `2026-07-28`. MUST rules: 26 pass, 3 fail, 6 not checkable from outside. SHOULD: 13 pass, 4 fail.

| Rule | What Sentinel saw |
|---|---|
| `MUST/missing-protocol-version-rejected` | a request omitting io.modelcontextprotocol/protocolVersion was rejected, but not as the spec requires: error code was -32600, not -32602 |
| `MUST/protocol-version-header-body-mismatch-rejected` | a header/body protocol-version mismatch was refused, but not as the spec requires: the JSON-RPC error code was -32600, not -32020 |
| `MUST/protocol-version-header-required` | a POST with no MCP-Protocol-Version header was refused, but not as the spec requires: the JSON-RPC error code was -32600, not -32020 |
| `SHOULD/get-delete-405` | GET → HTTP 400, DELETE → HTTP 400; the specification asks for 405 Method Not Allowed so that a client still speaking the previous transport is told at |
| `SENTINEL/STYLE/description-states-purpose` | 1 tool(s) have a stub description: ['greet'] |
| `SENTINEL/STYLE/parameters-are-described` | 3 of 3 parameter(s) have no description: ['add.a', 'add.b', 'greet.name'] |
| `SENTINEL/STYLE/tools-have-descriptions` | 1 tools have no description: ['greet'] |

## Official conformance reference server (TypeScript SDK)

Protocol generation detected: `2026-07-28`. MUST rules: 26 pass, 5 fail, 7 not checkable from outside. SHOULD: 12 pass, 5 fail.

| Rule | What Sentinel saw |
|---|---|
| `MUST/header-body-mismatch-rejected` | a request whose Mcp-Method header said tools/list while its body called tools/call was SERVED; a gateway routing on the header authorized a different  |
| `MUST/input-requests-respect-declared-capabilities` | test_input_required_result_elicitation, test_input_required_result_list_roots, test_input_required_result_multi_round, test_input_required_result_mult |
| `MUST/invalid-origin-rejected` | a request carrying Origin: https://sentinel-rebinding-probe.invalid was SERVED (HTTP 200). .invalid can never resolve, so no allowlist contains it and |
| `MUST/mcp-method-header-required` | tools/list was served with no Mcp-Method header; a header-based gateway policy in front of this server can be bypassed by omitting the header |
| `MUST/mcp-name-header-required` | tools/call 'test_simple_text' was served with no Mcp-Name header; a gateway authorizing one tool and not another cannot do so if the header naming the |
| `SHOULD/get-delete-405` | GET → HTTP 400, DELETE → HTTP 400; the specification asks for 405 Method Not Allowed so that a client still speaking the previous transport is told at |
| `SHOULD/malformed-json-is-parse-error` | malformed JSON produced no JSON-RPC error (HTTP 400) |
| `SHOULD/server-info-echoed` | 4 of 5 results omit serverInfo: ['tools/list', 'resources/list', 'resources/templates/list', 'prompts/list'] |
| `SENTINEL/STYLE/parameters-are-described` | 5 of 7 parameter(s) have no description: ['json_schema_2020_12_tool.name', 'json_schema_2020_12_tool.address', 'json_schema_2020_12_tool.contactMethod |
| `SENTINEL/STYLE/tools-sorted-by-name` | tools are not in byte-wise name order: ['test_simple_text', 'test_image_content', 'test_audio_content', 'test_embedded_resource', 'test_multiple_conte |
