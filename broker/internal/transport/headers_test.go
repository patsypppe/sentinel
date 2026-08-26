package transport

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
)

func req(method, params string) envelope.Request {
	return envelope.Request{
		JSONRPC: envelope.JSONRPCVersion,
		ID:      json.RawMessage(`1`),
		Method:  method,
		Params:  json.RawMessage(params),
	}
}

func hdr(method, name string) http.Header {
	h := http.Header{}
	if method != "" {
		h.Set(HeaderMcpMethod, method)
	}
	if name != "" {
		h.Set(HeaderMcpName, name)
	}
	return h
}

func TestHeadersAgreeingWithBodyPass(t *testing.T) {
	cases := []struct {
		desc   string
		req    envelope.Request
		method string
		name   string
	}{
		{
			desc:   "a method that takes no name sends no Mcp-Name",
			req:    req("tools/list", `{}`),
			method: "tools/list",
			name:   "",
		},
		{
			desc:   "tools/call names the tool",
			req:    req("tools/call", `{"name":"warehouse.query"}`),
			method: "tools/call",
			name:   "warehouse.query",
		},
		{
			desc:   "resources/read names the uri",
			req:    req("resources/read", `{"uri":"warehouse://schema/orders"}`),
			method: "resources/read",
			name:   "warehouse://schema/orders",
		},
		{
			desc:   "prompts/get names the prompt",
			req:    req("prompts/get", `{"name":"triage"}`),
			method: "prompts/get",
			name:   "triage",
		},
		{
			desc:   "server/discover likewise",
			req:    req("server/discover", ``),
			method: "server/discover",
			name:   "",
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			if err := ValidateHeaders(hdr(c.method, c.name), c.req); err != nil {
				t.Fatalf("valid headers rejected: %d %s", err.Code, err.Message)
			}
		})
	}
}

func TestMissingMcpMethodRejected(t *testing.T) {
	err := ValidateHeaders(hdr("", "tools/list"), req("tools/list", `{}`))
	if err == nil {
		t.Fatal("a request without Mcp-Method must be rejected: a gateway cannot route it")
	}
	if err.Code != envelope.CodeHeaderMismatch {
		t.Fatalf("code = %d, want %d", err.Code, envelope.CodeHeaderMismatch)
	}
}

// TestMissingMcpNameRejected. Mcp-Name is required for the three methods the
// specification's header table names, and tools/call is one of them: a gateway
// authorizing one tool and not another cannot do so if the header naming the
// tool is optional.
func TestMissingMcpNameRejected(t *testing.T) {
	err := ValidateHeaders(hdr("tools/call", ""), req("tools/call", `{"name":"warehouse.query"}`))
	if err == nil {
		t.Fatal("a tools/call without Mcp-Name must be rejected")
	}
	if err.Code != envelope.CodeHeaderMismatch {
		t.Fatalf("code = %d, want %d", err.Code, envelope.CodeHeaderMismatch)
	}
}

// TestMcpNameNotRequiredWhereTheSpecDoesNotDefineIt. The header table sources
// Mcp-Name from params.name or params.uri and requires it for tools/call,
// resources/read and prompts/get — "All requests" is Mcp-Method's row. Demanding
// it on tools/list would refuse a request that satisfies every MUST, which is
// what this server did until the §8.2 divergence was corrected.
func TestMcpNameNotRequiredWhereTheSpecDoesNotDefineIt(t *testing.T) {
	for _, method := range []string{"tools/list", "resources/list", "prompts/list", "server/discover"} {
		t.Run(method, func(t *testing.T) {
			if err := ValidateHeaders(hdr(method, ""), req(method, `{}`)); err != nil {
				t.Fatalf("a conformant %s with no Mcp-Name was refused: %d %s",
					method, err.Code, err.Message)
			}
		})
	}
}

// TestMcpNameOnAMethodThatHasNoNameRejected is the other half. The header is
// SOURCED FROM a body field, and the spec requires rejecting a header whose
// value does not match the corresponding body value. tools/list has no
// corresponding value at all, so the header asserts something the server cannot
// check — and a gateway that routed on it would have authorized a claim nobody
// verified.
func TestMcpNameOnAMethodThatHasNoNameRejected(t *testing.T) {
	err := ValidateHeaders(hdr("tools/list", "tools/list"), req("tools/list", `{}`))
	if err == nil {
		t.Fatal("an Mcp-Name on a method with no params.name or params.uri must be rejected")
	}
	if err.Code != envelope.CodeHeaderMismatch {
		t.Fatalf("code = %d, want %d", err.Code, envelope.CodeHeaderMismatch)
	}
	raw, _ := json.Marshal(err.Data)
	var data HeaderMismatchData
	_ = json.Unmarshal(raw, &data)
	if data.Header != HeaderMcpName {
		t.Fatalf("error names header %q, want %q", data.Header, HeaderMcpName)
	}
}

// TestHeaderBodyMismatchIsMinus32020 is the other half of the gateway
// demonstration: Envoy routes on the header, the broker rejects the body that
// disagrees with it. A body claiming a different method than the header is the
// exact shape of a request trying to slip past a header-based policy.
func TestHeaderBodyMismatchIsMinus32020(t *testing.T) {
	cases := []struct {
		desc   string
		req    envelope.Request
		method string
		name   string
		header string
	}{
		{
			desc:   "body claims a different method than the header",
			req:    req("tools/call", `{"name":"warehouse.query"}`),
			method: "tools/list",
			name:   "warehouse.query",
			header: HeaderMcpMethod,
		},
		{
			desc:   "body calls a different tool than the header",
			req:    req("tools/call", `{"name":"ops.deployment_apply"}`),
			method: "tools/call",
			name:   "warehouse.query",
			header: HeaderMcpName,
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			err := ValidateHeaders(hdr(c.method, c.name), c.req)
			if err == nil {
				t.Fatal("a header disagreeing with the body must be rejected")
			}
			if err.Code != envelope.CodeHeaderMismatch {
				t.Fatalf("code = %d, want %d", err.Code, envelope.CodeHeaderMismatch)
			}
			raw, _ := json.Marshal(err.Data)
			var data HeaderMismatchData
			_ = json.Unmarshal(raw, &data)
			if data.Header != c.header {
				t.Fatalf("error names header %q, want %q — the client cannot fix what it is not told",
					data.Header, c.header)
			}
		})
	}
}

// TestOpsToolCannotHideBehindAWarehouseHeader. This is the case the Envoy
// policy exists to stop, checked on the server side so the policy cannot be
// bypassed by a client that talks to the broker directly.
func TestOpsToolCannotHideBehindAWarehouseHeader(t *testing.T) {
	err := ValidateHeaders(
		hdr("tools/call", "warehouse.query"),
		req("tools/call", `{"name":"ops.deployment_apply","arguments":{}}`))
	if err == nil {
		t.Fatal("a body calling ops.deployment_apply behind a warehouse.query header must be rejected")
	}
	if err.Code != envelope.CodeHeaderMismatch {
		t.Fatalf("code = %d, want %d", err.Code, envelope.CodeHeaderMismatch)
	}
}

// TestNameBearingMethodRequiresTheName: tools/call with no name in params has
// nothing for Mcp-Name to match, and the error must say which field is missing.
func TestNameBearingMethodRequiresTheName(t *testing.T) {
	err := ValidateHeaders(hdr("tools/call", "warehouse.query"), req("tools/call", `{}`))
	if err == nil {
		t.Fatal("tools/call without params.name must be rejected")
	}
	if err.Code != envelope.CodeInvalidParams {
		t.Fatalf("code = %d, want %d (the body is malformed, not the header)",
			err.Code, envelope.CodeInvalidParams)
	}
}

// --- MCP-Protocol-Version ---------------------------------------------------

func versionHeader(value string) http.Header {
	h := http.Header{}
	if value != "" {
		h.Set(HeaderProtocolVersion, value)
	}
	return h
}

func metaWithVersion(version string) envelope.RequestMeta {
	return envelope.RequestMeta{ProtocolVersion: version}
}

// TestProtocolVersionHeaderMatrix walks every square of the table
// ValidateProtocolVersion documents. "Every POST request to the MCP endpoint
// MUST include an MCP-Protocol-Version header… The header value MUST match the
// io.modelcontextprotocol/protocolVersion field carried in the request body's
// _meta."
func TestProtocolVersionHeaderMatrix(t *testing.T) {
	cases := []struct {
		desc     string
		header   string
		body     string
		rejected bool
	}{
		{
			desc:     "header and body agree",
			header:   "2026-07-28",
			body:     "2026-07-28",
			rejected: false,
		},
		{
			desc:     "header absent while the body declares one",
			header:   "",
			body:     "2026-07-28",
			rejected: true,
		},
		{
			desc:     "header present while the body declares none",
			header:   "2026-07-28",
			body:     "",
			rejected: true,
		},
		{
			desc:     "header and body disagree",
			header:   "2025-11-25",
			body:     "2026-07-28",
			rejected: true,
		},
		{
			// Neither is present: a client that pre-dates both, or a current
			// client that dropped a required field. envelope.RequireMetaFields
			// owns that decision, and giving it two owners would give it two
			// error codes.
			desc:     "neither is present",
			header:   "",
			body:     "",
			rejected: false,
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			err := ValidateProtocolVersion(versionHeader(c.header), metaWithVersion(c.body))
			if c.rejected {
				if err == nil {
					t.Fatal("want a rejection")
				}
				if err.Code != envelope.CodeHeaderMismatch {
					t.Fatalf("code = %d, want %d", err.Code, envelope.CodeHeaderMismatch)
				}
				raw, _ := json.Marshal(err.Data)
				var data HeaderMismatchData
				_ = json.Unmarshal(raw, &data)
				if data.Header != HeaderProtocolVersion {
					t.Fatalf("error names header %q, want %q — the client cannot fix what it is not told",
						data.Header, HeaderProtocolVersion)
				}
				return
			}
			if err != nil {
				t.Fatalf("a conformant request was refused: %d %s", err.Code, err.Message)
			}
		})
	}
}

// TestProtocolVersionHeaderIsNotRoutingData. The other two headers exist so a
// gateway can route without parsing the body; this one exists so the revision a
// request runs under is visible on the wire. It is validated the same way for
// the same reason — a gateway that saw one version while another ran underneath
// it has authorized something that did not happen.
func TestProtocolVersionHeaderIsNotRoutingData(t *testing.T) {
	err := ValidateProtocolVersion(
		versionHeader("2025-11-25"), metaWithVersion("2026-07-28"))
	if err == nil {
		t.Fatal("a header naming a different revision than the body must be rejected")
	}
	raw, _ := json.Marshal(err.Data)
	var data HeaderMismatchData
	_ = json.Unmarshal(raw, &data)
	if data.HeaderValue != "2025-11-25" || data.BodyValue != "2026-07-28" {
		t.Fatalf("error data = %s; it must show both values so the disagreement is legible", raw)
	}
}
