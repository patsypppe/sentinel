package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

// post sends a request with headers derived from the body, the way a
// conformant client does. Tests that violate the contract on purpose use
// postRaw instead, so every violation is visible at the call site.
func post(t *testing.T, srv *httptest.Server, body string) envelope.Response {
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
	return postRaw(t, srv, body, headers)
}

func postRaw(t *testing.T, srv *httptest.Server, body string, headers map[string]string) envelope.Response {
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

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP %d: a JSON-RPC error is a successful exchange carrying an "+
			"application-level error, so the status must stay 200", resp.StatusCode)
	}
	var out envelope.Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDiscoverOverHTTPWithoutAVersion(t *testing.T) {
	srv := testServer(t)
	resp := post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`)

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
	resp := post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`)

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
			body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
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
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01"}}}`
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

	ok := post(t, srv, `{"jsonrpc":"2.0","id":"abc-123","method":"server/discover"}`)
	if string(ok.ID) != `"abc-123"` {
		t.Fatalf("success path id = %s, want \"abc-123\"", ok.ID)
	}

	bad := post(t, srv, `{"jsonrpc":"2.0","id":"abc-123","method":"nope"}`)
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

	// No _meta at all: the unversioned legacy fallback.
	post(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	if len(recorded) != 1 {
		t.Fatalf("recorded %v, want exactly one deprecation event", recorded)
	}
}

// TestHeaderContractEnforcedOverHTTP: the unit tests above prove the validator;
// this proves it is actually wired into the pipeline, which is a different
// failure mode and the one that reaches production.
func TestHeaderContractEnforcedOverHTTP(t *testing.T) {
	srv := testServer(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`

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
	resp := postRaw(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil)
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
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"warehouse.query","arguments":{}}}`,
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
