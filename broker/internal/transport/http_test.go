package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/patsypppe/sentinel/broker/internal/config"
	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/registry"
)

func testServer(t *testing.T) *httptest.Server {
	t.Helper()

	info := envelope.Info{Name: "sentinel-broker", Version: "test"}
	mux := NewMux()
	mux.Handle(envelope.MethodDiscover, DiscoverHandler(info, ""))
	mux.Handle(envelope.MethodToolsList, func(_ context.Context, _ json.RawMessage) (envelope.Result, *envelope.RPCError) {
		res := &envelope.ToolsListResult{Tools: []envelope.ToolDescriptor{}, ManifestHash: "sha256:test"}
		res.SetCache(envelope.DefaultToolsListCachePolicy)
		return res, nil
	})

	cfg := config.Default()
	s := NewServer(mux, cfg, info, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	return srv
}

// The minimum conformant `_meta` for a request in this revision, and the same
// with a declared version. clientCapabilities is Required: Yes on EVERY
// request, so a body literal that omits it is testing the -32602 path whether
// it means to or not — which is why these are constants rather than a habit.
const (
	capsMeta    = `"_meta":{"io.modelcontextprotocol/clientCapabilities":{}}`
	versionMeta = `"_meta":{"io.modelcontextprotocol/clientCapabilities":{},` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`
)

// post sends a request with headers derived from the body, the way a
// conformant client does. Tests that violate the contract on purpose use
// postRaw instead, so every violation is visible at the call site.
func post(t *testing.T, srv *httptest.Server, body string) envelope.Response {
	t.Helper()
	return postRaw(t, srv, body, conformantHeaders(t, body))
}

// conformantHeaders derives every required header from the body, which is what
// makes them checkable: each one is sourced from a body field, so a helper that
// invented a value would be testing the header contract against itself.
func conformantHeaders(t *testing.T, body string) map[string]string {
	t.Helper()

	var req envelope.Request
	_ = json.Unmarshal([]byte(body), &req)
	headers := map[string]string{HeaderMcpMethod: req.Method}
	// Mcp-Name only where the specification defines it. Sending it on a
	// tools/list would be a header asserting a body value that does not exist,
	// which this server refuses.
	if name, takesName, err := ExpectedMcpName(req); takesName && err == nil {
		headers[HeaderMcpName] = name
	}
	// MCP-Protocol-Version only when the body declares one to match. A body
	// with no version is an unversioned legacy request, and a header on one of
	// those asserts a version the body does not have.
	if meta, err := envelope.ExtractMeta(req.Params); err == nil && meta.ProtocolVersion != "" {
		headers[HeaderProtocolVersion] = meta.ProtocolVersion
	}
	return headers
}

// postRaw sends a request and checks the two transport-level guarantees that
// apply to EVERY response, so every test below asserts them without saying so:
// the Content-Type is one of the two the specification allows, and the status
// is the one httpStatusFor maps the error code to. The second replaces an
// older, blunter assertion that the status was always 200 — this revision
// fixes the status for five codes, and 200 for the rest is now a rule with
// named exceptions rather than a blanket.
func postRaw(t *testing.T, srv *httptest.Server, body string, headers map[string]string) envelope.Response {
	t.Helper()

	status, respHeaders, out := postFull(t, srv, body, headers)

	if ct := respHeaders.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q; the spec allows only application/json or text/event-stream", ct)
	}
	want := http.StatusOK
	if out.Error != nil {
		want = httpStatusFor(out.Error.Code)
	}
	if status != want {
		t.Fatalf("HTTP %d for JSON-RPC %+v, want %d", status, out.Error, want)
	}
	return out
}

// postFull is postRaw without the assertions, for the tests that are about the
// status line itself.
func postFull(
	t *testing.T, srv *httptest.Server, body string, headers map[string]string,
) (int, http.Header, envelope.Response) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out envelope.Response
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("response body is not JSON-RPC (HTTP %d): %q", resp.StatusCode, raw)
		}
	}
	return resp.StatusCode, resp.Header, out
}

func TestDiscoverOverHTTPWithoutAVersion(t *testing.T) {
	srv := testServer(t)
	resp := post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+capsMeta+`}}`)

	if resp.Error != nil {
		t.Fatalf("server/discover refused an unversioned request (%d %s) — the server is undiscoverable",
			resp.Error.Code, resp.Error.Message)
	}
	var res envelope.DiscoverResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.ResultType != envelope.ResultComplete {
		t.Fatalf("resultType = %q, want %q", res.ResultType, envelope.ResultComplete)
	}
	if len(res.SupportedVersions) == 0 {
		t.Fatal("server/discover must report supportedVersions")
	}
	if res.Meta == nil || res.Meta.ServerInfo == nil {
		t.Fatal("server/discover must echo serverInfo in _meta")
	}
	if res.TTLMs == 0 || res.CacheScope == "" {
		t.Fatal("server/discover is a CacheableResult and must carry ttlMs and cacheScope")
	}
}

// TestAdvertisedCapabilitiesAreTrue. §14 gotcha 10: advertising listChanged
// without subscriptions/listen makes the broker fail its own harness in front of
// an audience.
func TestAdvertisedCapabilitiesAreTrue(t *testing.T) {
	srv := testServer(t)
	resp := post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+capsMeta+`}}`)

	var res envelope.DiscoverResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.Capabilities.Tools.ListChanged {
		t.Error("tools.listChanged is advertised true but subscriptions/listen is not implemented")
	}
	if res.Capabilities.Resources.Subscribe {
		t.Error("resources.subscribe is advertised true but resources/subscribe was removed in this revision")
	}
	if len(res.Extensions) != 0 {
		t.Errorf("extensions %v advertised but none are implemented", res.Extensions)
	}
}

// TestRemovedMethodsReturnMethodNotFound. §9.1: removed methods must answer,
// not be silently absent from the router. A conformance rule checks this, so
// the broker must satisfy its own harness.
func TestRemovedMethodsReturnMethodNotFound(t *testing.T) {
	srv := testServer(t)

	for _, method := range []string{
		"ping",
		"initialize",
		"logging/setLevel",
		"notifications/roots/list_changed",
		"resources/subscribe",
		"resources/unsubscribe",
	} {
		t.Run(method, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{` + versionMeta + `}}`
			resp := post(t, srv, body)

			if resp.Error == nil {
				t.Fatalf("%s was served; it was removed in 2026-07-28", method)
			}
			if resp.Error.Code != envelope.CodeMethodNotFound {
				t.Fatalf("code = %d, want %d (method not found)", resp.Error.Code, envelope.CodeMethodNotFound)
			}
			// The provenance is what makes it actionable for a migrating client.
			raw, _ := json.Marshal(resp.Error.Data)
			var data envelope.RemovedMethodData
			_ = json.Unmarshal(raw, &data)
			if data.RemovedIn != "2026-07-28" {
				t.Fatalf("error data must name the revision that removed the method, got %s", raw)
			}
		})
	}
}

// TestRegisteringARemovedMethodPanics: better caught at boot than in front of
// an audience.
func TestRegisteringARemovedMethodPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("registering a removed method must panic at boot")
		}
	}()
	NewMux().Handle("ping", func(context.Context, json.RawMessage) (envelope.Result, *envelope.RPCError) {
		return nil, nil
	})
}

func TestUnsupportedVersionOnOrdinaryMethod(t *testing.T) {
	srv := testServer(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":` +
		`{"io.modelcontextprotocol/clientCapabilities":{},` +
		`"io.modelcontextprotocol/protocolVersion":"2099-01-01"}}}`
	resp := post(t, srv, body)

	if resp.Error == nil {
		t.Fatal("want -32022 for an unsupported version")
	}
	if resp.Error.Code != envelope.CodeUnsupportedProtocolVersion {
		t.Fatalf("code = %d, want %d", resp.Error.Code, envelope.CodeUnsupportedProtocolVersion)
	}
}

func TestMalformedJSONIsParseError(t *testing.T) {
	srv := testServer(t)
	resp := post(t, srv, `{"jsonrpc":"2.0",`)
	if resp.Error == nil || resp.Error.Code != envelope.CodeParseError {
		t.Fatalf("want %d, got %+v", envelope.CodeParseError, resp.Error)
	}
}

func TestWrongJSONRPCVersionIsRejected(t *testing.T) {
	srv := testServer(t)
	resp := post(t, srv, `{"jsonrpc":"1.0","id":1,"method":"server/discover"}`)
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidParams {
		t.Fatalf("want %d, got %+v", envelope.CodeInvalidParams, resp.Error)
	}
}

// TestResponsePreservesRequestID across both the success and error paths — a
// client correlating responses has nothing else to go on.
func TestResponsePreservesRequestID(t *testing.T) {
	srv := testServer(t)

	ok := post(t, srv, `{"jsonrpc":"2.0","id":"abc-123","method":"server/discover","params":{`+capsMeta+`}}`)
	if string(ok.ID) != `"abc-123"` {
		t.Fatalf("success path id = %s, want \"abc-123\"", ok.ID)
	}

	bad := post(t, srv, `{"jsonrpc":"2.0","id":"abc-123","method":"nope","params":{`+versionMeta+`}}`)
	if string(bad.ID) != `"abc-123"` {
		t.Fatalf("error path id = %s, want \"abc-123\"", bad.ID)
	}
}

// TestLegacyFallbackRecordsDeprecation: §8.1 requires the event, and a callback
// that never fires is the same as no requirement at all.
func TestLegacyFallbackRecordsDeprecation(t *testing.T) {
	info := envelope.Info{Name: "sentinel-broker", Version: "test"}
	mux := NewMux()
	mux.Handle(envelope.MethodToolsList, func(_ context.Context, _ json.RawMessage) (envelope.Result, *envelope.RPCError) {
		res := &envelope.ToolsListResult{Tools: []envelope.ToolDescriptor{}}
		res.SetCache(envelope.DefaultToolsListCachePolicy)
		return res, nil
	})

	var recorded []string
	s := NewServer(mux, config.Default(), info,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithDeprecationRecorder(func(_ context.Context, event, method string) {
			recorded = append(recorded, event+" "+method)
		}))
	srv := httptest.NewServer(s.Routes())
	defer srv.Close()

	// No declared version: the unversioned legacy fallback. clientCapabilities
	// is still there, because the fallback covers the version field and nothing
	// else — it is not a licence to omit the rest of the envelope.
	post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{`+capsMeta+`}}`)

	if len(recorded) != 1 {
		t.Fatalf("recorded %v, want exactly one deprecation event", recorded)
	}
}

// TestHeaderContractEnforcedOverHTTP: the unit tests above prove the validator;
// this proves it is actually wired into the pipeline, which is a different
// failure mode and the one that reaches production.
func TestHeaderContractEnforcedOverHTTP(t *testing.T) {
	srv := testServer(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + capsMeta + `}}`

	t.Run("no headers at all", func(t *testing.T) {
		resp := postRaw(t, srv, body, nil)
		if resp.Error == nil || resp.Error.Code != envelope.CodeHeaderMismatch {
			t.Fatalf("want %d, got %+v", envelope.CodeHeaderMismatch, resp.Error)
		}
	})

	t.Run("header disagrees with body", func(t *testing.T) {
		resp := postRaw(t, srv, body, map[string]string{
			HeaderMcpMethod: "tools/list",
			HeaderMcpName:   "tools/list",
		})
		if resp.Error == nil || resp.Error.Code != envelope.CodeHeaderMismatch {
			t.Fatalf("want %d, got %+v", envelope.CodeHeaderMismatch, resp.Error)
		}
	})

	t.Run("headers agree", func(t *testing.T) {
		// No Mcp-Name: server/discover has no params.name or params.uri, so
		// the header is not defined for it and sending one is itself a
		// mismatch.
		resp := postRaw(t, srv, body, map[string]string{
			HeaderMcpMethod: "server/discover",
		})
		if resp.Error != nil {
			t.Fatalf("conformant headers rejected: %d %s", resp.Error.Code, resp.Error.Message)
		}
	})

	t.Run("Mcp-Name on a method that takes none", func(t *testing.T) {
		resp := postRaw(t, srv, body, map[string]string{
			HeaderMcpMethod: "server/discover",
			HeaderMcpName:   "server/discover",
		})
		if resp.Error == nil || resp.Error.Code != envelope.CodeHeaderMismatch {
			t.Fatalf("want %d, got %+v", envelope.CodeHeaderMismatch, resp.Error)
		}
	})
}

// TestHeaderContractIsCheckedBeforeNegotiation. Ordering matters: §9.1 puts the
// header contract first so a gateway's routing decision is validated before any
// protocol work happens. A request with both a bad header and no version must
// report the header problem, not the version one.
func TestHeaderContractIsCheckedBeforeNegotiation(t *testing.T) {
	srv := testServer(t)
	resp := postRaw(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{`+capsMeta+`}}`, nil)
	if resp.Error == nil {
		t.Fatal("want an error")
	}
	if resp.Error.Code != envelope.CodeHeaderMismatch {
		t.Fatalf("code = %d, want %d: the header contract is validated before negotiation",
			resp.Error.Code, envelope.CodeHeaderMismatch)
	}
}

// --- data.legacyCode through the transition ---------------------------------

// scopedTool declares a scope so the tests below can provoke a REAL scope
// denial through the real pipeline. A handler that simply returned
// CodeScopeDenied would prove only that writeError can serialize a number.
type scopedTool struct{}

func (scopedTool) Name() string        { return "warehouse.query" }
func (scopedTool) Description() string { return "a tool that requires a scope its caller lacks" }
func (scopedTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`)
}
func (scopedTool) OutputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"rows":{"type":"array"}}}`)
}
func (scopedTool) Scopes() []string                      { return []string{"warehouse:read"} }
func (scopedTool) Reversibility() registry.Reversibility { return registry.Reversible }
func (scopedTool) CachePolicy() envelope.CachePolicy {
	return envelope.CachePolicy{TTLMs: 300_000, Scope: envelope.ScopePrivate}
}
func (scopedTool) TokenCap() int { return 25_000 }
func (scopedTool) Call(context.Context, registry.Principal, json.RawMessage) (registry.Result, error) {
	return &envelope.ToolsCallResult{}, nil
}

// scopeDeniedServer serves tools/call with one scoped tool, and authenticates
// every request as a principal that holds no scopes at all.
func scopeDeniedServer(t *testing.T, opts ...Option) *httptest.Server {
	t.Helper()

	reg, err := registry.New(scopedTool{})
	if err != nil {
		t.Fatal(err)
	}
	info := envelope.Info{Name: "sentinel-broker", Version: "test"}
	mux := NewMux()
	mux.Handle(envelope.MethodToolsCall, ToolsCallHandler(reg))

	opts = append(opts, WithAuthenticator(DevAuthenticator{Enabled: true, Tenant: "t1"}))
	s := NewServer(mux, config.Default(), info, slog.New(slog.NewTextHandler(io.Discard, nil)), opts...)
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	return srv
}

// denyScope calls the scoped tool with a scopeless principal and returns the
// refusal, having first checked that it is the refusal we meant to provoke.
func denyScope(t *testing.T, srv *httptest.Server) *envelope.RPCError {
	t.Helper()

	resp := postRaw(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"warehouse.query",`+
			`"arguments":{},`+capsMeta+`}}`,
		map[string]string{
			HeaderMcpMethod: envelope.MethodToolsCall,
			HeaderMcpName:   "warehouse.query",
			HeaderPrincipal: "alice",
			// HeaderScopes is deliberately absent: alice holds nothing.
		})
	if resp.Error == nil {
		t.Fatal("tools/call succeeded for a principal holding none of the tool's scopes")
	}
	if resp.Error.Code != envelope.CodeScopeDenied {
		t.Fatalf("code = %d, want %d (scope denied)", resp.Error.Code, envelope.CodeScopeDenied)
	}
	return resp.Error
}

// errorDataKeys decodes error.data as an object so a test can ask whether a key
// is present, not merely whether it decoded to a zero value. Going through
// json.RawMessage keeps the numbers integers: a number read through `any`
// becomes a float64 and stops comparing equal to the constant it came from.
func errorDataKeys(t *testing.T, rpcErr *envelope.RPCError) map[string]json.RawMessage {
	t.Helper()

	if rpcErr.Data == nil {
		return nil
	}
	raw, err := json.Marshal(rpcErr.Data)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("error data is not a JSON object: %s", raw)
	}
	return keys
}

// TestErrorCarriesLegacyCodeDuringTransition. A client that triaged on -32007
// through v0.1.0 must be able to keep doing so for one release.
func TestErrorCarriesLegacyCodeDuringTransition(t *testing.T) {
	rpcErr := denyScope(t, scopeDeniedServer(t, WithLegacyErrorCodes(true)))

	keys := errorDataKeys(t, rpcErr)
	raw, ok := keys["legacyCode"]
	if !ok {
		t.Fatalf("error data carries no legacyCode: %v", keys)
	}
	var legacy int
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatalf("legacyCode is not an integer: %s", raw)
	}
	if legacy != -32007 {
		t.Errorf("legacyCode = %d, want -32007", legacy)
	}
}

// TestLegacyCodeIsOmittedWhenDisabled. The transition aid is a transition aid:
// turning it off must leave no trace of the retired number.
func TestLegacyCodeIsOmittedWhenDisabled(t *testing.T) {
	rpcErr := denyScope(t, scopeDeniedServer(t, WithLegacyErrorCodes(false)))

	if keys := errorDataKeys(t, rpcErr); keys != nil {
		if _, present := keys["legacyCode"]; present {
			t.Errorf("legacyCode is present with the option off: %v", keys)
		}
	}
}

// --- the HTTP layer: status codes, Origin, Content-Type, notifications ------
//
// Everything below is the transport's own contract rather than JSON-RPC's, and
// the specification fixes each one with a MUST. postRaw already asserts the
// Content-Type and the code→status mapping on every other test in this file;
// these are the cases where the status line IS the behaviour under test.

// originServer builds a server with an explicit Origin allowlist. Everything
// else is testServer.
func originServer(t *testing.T, allowed ...string) *httptest.Server {
	t.Helper()

	info := envelope.Info{Name: "sentinel-broker", Version: "test"}
	mux := NewMux()
	mux.Handle(envelope.MethodDiscover, DiscoverHandler(info, ""))

	cfg := config.Default()
	cfg.AllowedOrigins = allowed
	s := NewServer(mux, cfg, info, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	return srv
}

// rawRequest issues a request and returns the status, the response headers and
// the UNDECODED body. The tests below are about the status line and the exact
// bytes, so they must not go through a decoder that would hide either.
func rawRequest(
	t *testing.T, srv *httptest.Server, method, path, body string, headers map[string]string,
) (int, http.Header, []byte) {
	t.Helper()

	req, err := http.NewRequest(method, srv.URL+path, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, raw
}

// TestUnknownMethodIsHTTP404. "If the server does not implement the requested
// RPC method, it MUST respond with 404 Not Found and a JSON-RPC error with code
// -32601." Both halves: a -32601 inside a 200 is as wrong as a bare 404.
func TestUnknownMethodIsHTTP404(t *testing.T) {
	srv := testServer(t)

	for _, method := range []string{
		"sentinel/definitely-not-a-real-method",
		// A method this revision REMOVED is also a method this server does not
		// implement. It answers with provenance, but it answers 404.
		"ping",
	} {
		t.Run(method, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{` + versionMeta + `}}`
			status, _, resp := postFull(t, srv, body, conformantHeaders(t, body))

			if resp.Error == nil || resp.Error.Code != envelope.CodeMethodNotFound {
				t.Fatalf("want %d, got %+v", envelope.CodeMethodNotFound, resp.Error)
			}
			if status != http.StatusNotFound {
				t.Fatalf("HTTP %d for an unimplemented method, want 404", status)
			}
		})
	}
}

// mustJSON fails the test unless raw is JSON, and returns it. A response body
// that is not JSON at all is the failure mode the Content-Type rule exists to
// prevent, and it deserves a message that says so.
func mustJSON(t *testing.T, raw []byte) []byte {
	t.Helper()
	if !json.Valid(raw) {
		t.Fatalf("response body is not JSON: %q", raw)
	}
	return raw
}

// TestErrorStatusesAreTheOnesTheSpecNames walks the four codes the
// specification assigns a status to, provoked through the real pipeline rather
// than by handing writeError a number.
func TestErrorStatusesAreTheOnesTheSpecNames(t *testing.T) {
	srv := testServer(t)

	cases := []struct {
		desc    string
		body    string
		headers map[string]string
		code    int
		status  int
	}{
		{
			desc:    "-32020 header mismatch",
			body:    `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + capsMeta + `}}`,
			headers: map[string]string{HeaderMcpMethod: "tools/list"},
			code:    envelope.CodeHeaderMismatch,
			status:  http.StatusBadRequest,
		},
		{
			desc: "-32022 unsupported protocol version",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":` +
				`{"io.modelcontextprotocol/clientCapabilities":{},` +
				`"io.modelcontextprotocol/protocolVersion":"2099-01-01"}}}`,
			headers: map[string]string{
				HeaderMcpMethod:       "tools/list",
				HeaderProtocolVersion: "2099-01-01",
			},
			code:   envelope.CodeUnsupportedProtocolVersion,
			status: http.StatusBadRequest,
		},
		{
			desc: "-32602 a required _meta field is missing",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
			headers: map[string]string{
				HeaderMcpMethod: "tools/list",
			},
			code:   envelope.CodeInvalidParams,
			status: http.StatusBadRequest,
		},
		{
			desc:    "-32601 unknown method",
			body:    `{"jsonrpc":"2.0","id":1,"method":"nope","params":{` + versionMeta + `}}`,
			headers: map[string]string{HeaderMcpMethod: "nope", HeaderProtocolVersion: "2026-07-28"},
			code:    envelope.CodeMethodNotFound,
			status:  http.StatusNotFound,
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			status, _, resp := postFull(t, srv, c.body, c.headers)
			if resp.Error == nil || resp.Error.Code != c.code {
				t.Fatalf("code = %+v, want %d", resp.Error, c.code)
			}
			if status != c.status {
				t.Fatalf("HTTP %d for %d, want %d", status, c.code, c.status)
			}
		})
	}
}

// TestApplicationErrorsStayHTTP200. The complement, and the reason the mapping
// is a table rather than "4xx on anything that failed": a denied scope is the
// working outcome of a successful exchange, and promoting it to 4xx would make
// every gateway in front of this server retry and alert on a refusal that is
// behaving exactly as designed.
func TestApplicationErrorsStayHTTP200(t *testing.T) {
	srv := scopeDeniedServer(t)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"warehouse.query",` +
		`"arguments":{},` + versionMeta + `}}`
	status, _, resp := postFull(t, srv, body, map[string]string{
		HeaderMcpMethod:       envelope.MethodToolsCall,
		HeaderMcpName:         "warehouse.query",
		HeaderProtocolVersion: "2026-07-28",
		HeaderPrincipal:       "alice",
	})

	if resp.Error == nil || resp.Error.Code != envelope.CodeScopeDenied {
		t.Fatalf("want %d, got %+v", envelope.CodeScopeDenied, resp.Error)
	}
	if status != http.StatusOK {
		t.Fatalf("HTTP %d for a scope denial; the specification names no status for it, so it is 200",
			status)
	}
}

// TestOriginIsValidated. "Servers MUST validate the Origin header on all
// incoming connections to prevent DNS rebinding attacks. If the Origin header
// is present and invalid, servers MUST respond with HTTP 403 Forbidden."
func TestOriginIsValidated(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + capsMeta + `}}`
	headers := func(origin string) map[string]string {
		h := map[string]string{
			"Content-Type":  "application/json",
			HeaderMcpMethod: envelope.MethodDiscover,
		}
		if origin != "" {
			h["Origin"] = origin
		}
		return h
	}

	t.Run("no Origin is unaffected", func(t *testing.T) {
		// Every non-browser client, which is every client this server expects.
		srv := originServer(t)
		status, _, _ := rawRequest(t, srv, http.MethodPost, "/mcp", body, headers(""))
		if status != http.StatusOK {
			t.Fatalf("HTTP %d for a request with no Origin; only a PRESENT Origin is validated", status)
		}
	})

	t.Run("an Origin with an empty allowlist is refused", func(t *testing.T) {
		// The default. A server with no browser clients should never see one,
		// and defaulting to permissive would ship the hole the requirement
		// exists to close.
		srv := originServer(t)
		status, respHeaders, raw := rawRequest(t, srv, http.MethodPost, "/mcp", body,
			headers("https://sentinel-rebinding-probe.invalid"))

		if status != http.StatusForbidden {
			t.Fatalf("HTTP %d for a disallowed Origin, want 403", status)
		}
		if ct := respHeaders.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("Content-Type = %q on the 403", ct)
		}
		// "The HTTP response body MAY comprise a JSON-RPC error response that
		// has no id." No id, because the body may not have been parsed at all.
		var envelopeBody map[string]json.RawMessage
		if err := json.Unmarshal(mustJSON(t, raw), &envelopeBody); err != nil {
			t.Fatal(err)
		}
		if _, present := envelopeBody["id"]; present {
			t.Errorf("the 403 body carries an id: %s", raw)
		}
		if _, present := envelopeBody["error"]; !present {
			t.Errorf("the 403 body carries no JSON-RPC error: %s", raw)
		}
	})

	t.Run("an allowlisted Origin is served", func(t *testing.T) {
		srv := originServer(t, "https://console.example.com")
		status, _, _ := rawRequest(t, srv, http.MethodPost, "/mcp", body,
			headers("https://console.example.com"))
		if status != http.StatusOK {
			t.Fatalf("HTTP %d for an allowlisted Origin", status)
		}
	})

	t.Run("matching is case-insensitive but not fuzzy", func(t *testing.T) {
		srv := originServer(t, "https://console.example.com")

		status, _, _ := rawRequest(t, srv, http.MethodPost, "/mcp", body,
			headers("https://CONSOLE.example.com"))
		if status != http.StatusOK {
			t.Errorf("HTTP %d: RFC 6454 compares a scheme and host case-insensitively", status)
		}

		// The near-miss an allowlist exists to catch.
		status, _, _ = rawRequest(t, srv, http.MethodPost, "/mcp", body,
			headers("https://console.example.com.evil.test"))
		if status != http.StatusForbidden {
			t.Errorf("HTTP %d for a suffix-extended lookalike Origin, want 403", status)
		}
	})

	t.Run("the check runs before the body is parsed", func(t *testing.T) {
		// A page that can reach this server has already won; it must not get as
		// far as a parse error, which would confirm the endpoint speaks MCP.
		srv := originServer(t)
		status, _, _ := rawRequest(t, srv, http.MethodPost, "/mcp", `{not json`,
			headers("https://sentinel-rebinding-probe.invalid"))
		if status != http.StatusForbidden {
			t.Fatalf("HTTP %d, want 403: Origin is validated before the body is read", status)
		}
	})
}

// TestGetAndDeleteAreRefusedWith405. "HTTP GET or DELETE to the MCP endpoint:
// respond with 405 Method Not Allowed." Both verbs opened or closed a session
// in the previous revision; there are no sessions here.
func TestGetAndDeleteAreRefusedWith405(t *testing.T) {
	srv := testServer(t)

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			status, respHeaders, raw := rawRequest(t, srv, method, "/mcp", "", nil)

			if status != http.StatusMethodNotAllowed {
				t.Fatalf("HTTP %d for a %s, want 405", status, method)
			}
			if allow := respHeaders.Get("Allow"); allow != http.MethodPost {
				t.Errorf("Allow = %q, want %q: a 405 that does not say what IS allowed "+
					"leaves the client guessing", allow, http.MethodPost)
			}
			if ct := respHeaders.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q on the 405", ct)
			}
			mustJSON(t, raw)
		})
	}
}

// TestNotificationIsNotAnsweredWithAResult. "If the body is a JSON-RPC
// notification: If the server accepts it, the server MUST return HTTP status
// code 202 Accepted with no body. If the server cannot accept it, it MUST
// return an HTTP error status code."
//
// This revision defines no client-to-server notification over Streamable HTTP,
// so there is nothing this server could honestly accept — but whatever it does,
// it must not answer with a result the client has no id to correlate.
func TestNotificationIsNotAnsweredWithAResult(t *testing.T) {
	srv := testServer(t)

	body := `{"jsonrpc":"2.0","method":"notifications/sentinel-probe","params":{` + capsMeta + `}}`
	status, _, raw := rawRequest(t, srv, http.MethodPost, "/mcp", body, map[string]string{
		"Content-Type":  "application/json",
		HeaderMcpMethod: "notifications/sentinel-probe",
	})

	switch {
	case status == http.StatusAccepted:
		if len(bytes.TrimSpace(raw)) != 0 {
			t.Fatalf("202 Accepted carried a body; the spec says \"with no body\": %q", raw)
		}
	case status >= 400:
		var resp envelope.Response
		if err := json.Unmarshal(mustJSON(t, raw), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Result != nil {
			t.Fatalf("a notification was answered with a result: %s", resp.Result)
		}
		if len(resp.ID) != 0 {
			t.Fatalf("the refusal invented an id the request never carried: %s", resp.ID)
		}
	default:
		t.Fatalf("a notification was answered with HTTP %d; want 202 or an error status: %s",
			status, raw)
	}
}

// TestANullIDIsNotANotification. A notification is a request with NO id.
// `"id": null` is a request carrying a null id — malformed by JSON-RPC's own
// rules, but not a notification, and conflating the two would silently swallow
// a real request.
func TestANullIDIsNotANotification(t *testing.T) {
	srv := testServer(t)

	body := `{"jsonrpc":"2.0","id":null,"method":"server/discover","params":{` + capsMeta + `}}`
	status, _, raw := rawRequest(t, srv, http.MethodPost, "/mcp", body, map[string]string{
		"Content-Type":  "application/json",
		HeaderMcpMethod: envelope.MethodDiscover,
	})

	if status != http.StatusOK {
		t.Fatalf("HTTP %d for a request with a null id: it is a request, not a notification: %s",
			status, raw)
	}
	var resp envelope.Response
	if err := json.Unmarshal(mustJSON(t, raw), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Result == nil {
		t.Fatalf("a request with a null id was not served: %s", raw)
	}
}

// TestProtocolVersionHeaderIsEnforcedOverHTTP walks the matrix
// ValidateProtocolVersion documents, through the real pipeline. The unit tests
// in headers_test.go prove the validator; this proves it is wired in, which is
// the failure mode that reaches production.
func TestProtocolVersionHeaderIsEnforcedOverHTTP(t *testing.T) {
	srv := testServer(t)
	versioned := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + versionMeta + `}}`

	t.Run("absent while the body declares one", func(t *testing.T) {
		status, _, resp := postFull(t, srv, versioned, map[string]string{
			HeaderMcpMethod: envelope.MethodToolsList,
		})
		if resp.Error == nil || resp.Error.Code != envelope.CodeHeaderMismatch {
			t.Fatalf("want %d, got %+v", envelope.CodeHeaderMismatch, resp.Error)
		}
		if status != http.StatusBadRequest {
			t.Fatalf("HTTP %d, want 400", status)
		}
	})

	t.Run("present but disagreeing with the body", func(t *testing.T) {
		// The gateway case: a proxy routing on the header would have authorized
		// one revision while another ran underneath it.
		status, _, resp := postFull(t, srv, versioned, map[string]string{
			HeaderMcpMethod:       envelope.MethodToolsList,
			HeaderProtocolVersion: "2025-11-25",
		})
		if resp.Error == nil || resp.Error.Code != envelope.CodeHeaderMismatch {
			t.Fatalf("want %d, got %+v", envelope.CodeHeaderMismatch, resp.Error)
		}
		if status != http.StatusBadRequest {
			t.Fatalf("HTTP %d, want 400", status)
		}
	})

	t.Run("present while the body declares none", func(t *testing.T) {
		unversioned := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + capsMeta + `}}`
		_, _, resp := postFull(t, srv, unversioned, map[string]string{
			HeaderMcpMethod:       envelope.MethodToolsList,
			HeaderProtocolVersion: "2026-07-28",
		})
		if resp.Error == nil || resp.Error.Code != envelope.CodeHeaderMismatch {
			t.Fatalf("want %d, got %+v: the header asserts a version the body does not carry",
				envelope.CodeHeaderMismatch, resp.Error)
		}
	})

	t.Run("agreeing is served", func(t *testing.T) {
		if resp := post(t, srv, versioned); resp.Error != nil {
			t.Fatalf("a conformant request was refused: %d %s", resp.Error.Code, resp.Error.Message)
		}
	})

	t.Run("absent everywhere is the legacy fallback", func(t *testing.T) {
		// BROKER_ALLOW_LEGACY_UNVERSIONED is on by default, and this is the one
		// square of the matrix it governs.
		unversioned := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + capsMeta + `}}`
		if resp := post(t, srv, unversioned); resp.Error != nil {
			t.Fatalf("the legacy fallback stopped working: %d %s", resp.Error.Code, resp.Error.Message)
		}
	})
}

// TestRequiredMetaFieldsAreEnforcedOverHTTP. "A request missing any required
// field is malformed; the server MUST reject it with JSON-RPC error code -32602
// (Invalid params). On HTTP, the response status MUST be 400 Bad Request."
func TestRequiredMetaFieldsAreEnforcedOverHTTP(t *testing.T) {
	srv := testServer(t)

	t.Run("clientCapabilities is required", func(t *testing.T) {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":` +
			`{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
		status, _, resp := postFull(t, srv, body, conformantHeaders(t, body))

		if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidParams {
			t.Fatalf("want %d, got %+v", envelope.CodeInvalidParams, resp.Error)
		}
		if status != http.StatusBadRequest {
			t.Fatalf("HTTP %d, want 400", status)
		}
	})

	t.Run("clientCapabilities is required on server/discover too", func(t *testing.T) {
		body := `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`
		_, _, resp := postFull(t, srv, body, conformantHeaders(t, body))
		if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidParams {
			t.Fatalf("want %d, got %+v: discovery is exempt from declaring a VERSION, "+
				"not from declaring what the client can do", envelope.CodeInvalidParams, resp.Error)
		}
	})

	t.Run("clientInfo is optional", func(t *testing.T) {
		// Required: No. Demanding it would refuse a request that satisfies
		// every MUST — the mirror-image defect of serving one that does not.
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + versionMeta + `}}`
		if resp := post(t, srv, body); resp.Error != nil {
			t.Fatalf("a request without clientInfo was refused (%d %s); the field is Required: No",
				resp.Error.Code, resp.Error.Message)
		}
	})

	t.Run("an unversioned request survives the legacy fallback", func(t *testing.T) {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + capsMeta + `}}`
		if resp := post(t, srv, body); resp.Error != nil {
			t.Fatalf("want a served request under BROKER_ALLOW_LEGACY_UNVERSIONED, got %d %s",
				resp.Error.Code, resp.Error.Message)
		}
	})
}

// TestUnversionedRequestIsRefusedWithTheFallbackOff is the other half: with the
// fallback off, an absent version is the malformed request the specification
// describes, and the code is -32602 rather than a negotiation failure — nothing
// was negotiated, because the request was never well-formed enough to negotiate.
func TestUnversionedRequestIsRefusedWithTheFallbackOff(t *testing.T) {
	info := envelope.Info{Name: "sentinel-broker", Version: "test"}
	mux := NewMux()
	mux.Handle(envelope.MethodDiscover, DiscoverHandler(info, ""))
	mux.Handle(envelope.MethodToolsList, func(_ context.Context, _ json.RawMessage) (envelope.Result, *envelope.RPCError) {
		res := &envelope.ToolsListResult{Tools: []envelope.ToolDescriptor{}}
		res.SetCache(envelope.DefaultToolsListCachePolicy)
		return res, nil
	})

	cfg := config.Default()
	cfg.AllowLegacyUnversioned = false
	s := NewServer(mux, cfg, info, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(s.Routes())
	defer srv.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + capsMeta + `}}`
	status, _, resp := postFull(t, srv, body, conformantHeaders(t, body))
	if resp.Error == nil || resp.Error.Code != envelope.CodeInvalidParams {
		t.Fatalf("want %d, got %+v", envelope.CodeInvalidParams, resp.Error)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("HTTP %d, want 400", status)
	}

	// And discovery still answers, because a client cannot name a version
	// before it has been told which versions exist.
	discover := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{` + capsMeta + `}}`
	if r := post(t, srv, discover); r.Error != nil {
		t.Fatalf("server/discover was refused for not naming a version (%d %s) — "+
			"the server is undiscoverable", r.Error.Code, r.Error.Message)
	}
}
