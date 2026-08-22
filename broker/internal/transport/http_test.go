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
	name, _ := ExpectedMcpName(req)
	if name == "" {
		name = req.Method
	}
	return postRaw(t, srv, body, map[string]string{
		HeaderMcpMethod: req.Method,
		HeaderMcpName:   name,
	})
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
		resp := postRaw(t, srv, body, map[string]string{
			HeaderMcpMethod: "server/discover",
			HeaderMcpName:   "server/discover",
		})
		if resp.Error != nil {
			t.Fatalf("conformant headers rejected: %d %s", resp.Error.Code, resp.Error.Message)
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
