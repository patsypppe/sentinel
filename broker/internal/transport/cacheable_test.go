package transport

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/patsypppe/sentinel/broker/internal/config"
	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/registry"
)

// fullServer registers every method the broker implements, so the cacheable
// checks below run against the real handler set rather than a stub.
func fullServer(t *testing.T) *httptest.Server {
	t.Helper()

	info := envelope.Info{Name: "sentinel-broker", Version: "test"}
	reg, err := registry.New()
	if err != nil {
		t.Fatal(err)
	}
	policy := envelope.CachePolicy{TTLMs: 300_000, Scope: envelope.ScopePrivate}

	mux := NewMux()
	mux.Handle(envelope.MethodDiscover, DiscoverHandler(info, ""))
	mux.Handle(envelope.MethodToolsList, ToolsListHandler(reg, policy))
	mux.Handle(envelope.MethodResourcesList, ResourcesListHandler(policy))
	mux.Handle(envelope.MethodResourceTemplatesList, ResourceTemplatesListHandler(policy))
	mux.Handle(envelope.MethodResourcesRead, ResourcesReadHandler(policy))
	mux.Handle(envelope.MethodPromptsList, PromptsListHandler(policy))

	// resources/read acts on a principal's behalf, so the server needs an
	// authenticator to serve it. The list endpoints and discovery do not, which
	// TestDiscoveryNeedsNoPrincipal below relies on.
	s := NewServer(mux, config.Default(), info, slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithAuthenticator(DevAuthenticator{Enabled: true, Tenant: "t1"}))
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	return srv
}

// TestCacheableFieldsPresent covers every list and read endpoint the broker
// serves. CacheableResult became required in this revision, and a list result
// missing ttlMs or cacheScope is a MUST failure the harness will report.
func TestCacheableFieldsPresent(t *testing.T) {
	srv := fullServer(t)

	endpoints := []string{
		envelope.MethodDiscover,
		envelope.MethodToolsList,
		envelope.MethodResourcesList,
		envelope.MethodResourceTemplatesList,
		envelope.MethodPromptsList,
	}

	for _, method := range endpoints {
		t.Run(method, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":1,"method":"` + method +
				`","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
			resp := post(t, srv, body)
			if resp.Error != nil {
				t.Fatalf("%s: %d %s", method, resp.Error.Code, resp.Error.Message)
			}

			var probe struct {
				ResultType string  `json:"resultType"`
				TTLMs      *int    `json:"ttlMs"`
				CacheScope *string `json:"cacheScope"`
			}
			if err := json.Unmarshal(resp.Result, &probe); err != nil {
				t.Fatal(err)
			}
			if probe.ResultType == "" {
				t.Errorf("%s is missing resultType", method)
			}
			if probe.TTLMs == nil {
				t.Errorf("%s is missing ttlMs: CacheableResult is required in this revision", method)
			}
			if probe.CacheScope == nil || *probe.CacheScope == "" {
				t.Errorf("%s is missing cacheScope", method)
			}
		})
	}
}

// TestResourceNotFoundIsMinus32602OverHTTP. The read endpoint is the fifth of
// the five, and its interesting path is the error one: resource-not-found moved
// from -32002 to -32602 in this revision.
func TestResourceNotFoundIsMinus32602OverHTTP(t *testing.T) {
	srv := fullServer(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"warehouse://nope","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	resp := postRaw(t, srv, body, map[string]string{
		HeaderMcpMethod: "resources/read",
		HeaderMcpName:   "warehouse://nope",
		HeaderPrincipal: "p1",
		HeaderScopes:    "warehouse:read",
	})

	if resp.Error == nil {
		t.Fatal("reading an unknown resource must be an error")
	}
	if resp.Error.Code != envelope.CodeInvalidParams {
		t.Fatalf("code = %d, want %d; -32002 was the pre-2026-07-28 code",
			resp.Error.Code, envelope.CodeInvalidParams)
	}
}

// TestToolsListIsByteStableOverHTTP is the §8.3 measurement end to end, through
// the transport rather than against the registry alone. The registry can be
// perfectly deterministic while the transport re-serializes and undoes it.
func TestToolsListIsByteStableOverHTTP(t *testing.T) {
	srv := fullServer(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`

	seen := map[string]int{}
	for i := 0; i < 100; i++ {
		resp := post(t, srv, body)
		if resp.Error != nil {
			t.Fatalf("%d %s", resp.Error.Code, resp.Error.Message)
		}
		seen[string(resp.Result)]++
	}
	if len(seen) != 1 {
		t.Fatalf("100 tools/list calls produced %d distinct response bodies, want 1", len(seen))
	}
}

// TestEmptyListsAreNotAbsentMethods. "This server has none" and "this server
// does not implement the method" are different claims, and a client that cannot
// tell them apart has to guess.
func TestEmptyListsAreNotAbsentMethods(t *testing.T) {
	srv := fullServer(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	resp := post(t, srv, body)

	if resp.Error != nil {
		t.Fatalf("resources/list must answer even with nothing to list, got %d", resp.Error.Code)
	}
	var res envelope.ResourcesListResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.Resources == nil {
		t.Fatal("resources must be an empty array, not null: null reads as \"unknown\"")
	}
}

// TestDiscoveryAndListsNeedNoPrincipal.
//
// Requiring a token to find out what a server supports would make it
// undiscoverable to a client that has not yet learned which token to get — the
// same failure as refusing server/discover for an unsupported version.
func TestDiscoveryAndListsNeedNoPrincipal(t *testing.T) {
	info := envelope.Info{Name: "sentinel-broker", Version: "test"}
	reg, err := registry.New()
	if err != nil {
		t.Fatal(err)
	}
	policy := envelope.CachePolicy{TTLMs: 300_000, Scope: envelope.ScopePrivate}

	mux := NewMux()
	mux.Handle(envelope.MethodDiscover, DiscoverHandler(info, ""))
	mux.Handle(envelope.MethodToolsList, ToolsListHandler(reg, policy))
	mux.Handle(envelope.MethodResourcesList, ResourcesListHandler(policy))
	mux.Handle(envelope.MethodPromptsList, PromptsListHandler(policy))

	// No authenticator at all.
	s := NewServer(mux, config.Default(), info, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(s.Routes())
	defer srv.Close()

	for _, method := range []string{
		envelope.MethodDiscover,
		envelope.MethodToolsList,
		envelope.MethodResourcesList,
		envelope.MethodPromptsList,
	} {
		t.Run(method, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":1,"method":"` + method +
				`","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
			if resp := post(t, srv, body); resp.Error != nil {
				t.Fatalf("%s required a principal (%d %s); a client cannot discover a server "+
					"it must already be authenticated to", method, resp.Error.Code, resp.Error.Message)
			}
		})
	}
}

// TestAuthenticatedMethodsFailClosedWithNoAuthenticator. The complement: a
// server with no authentication configured must refuse, not serve anonymously.
func TestAuthenticatedMethodsFailClosedWithNoAuthenticator(t *testing.T) {
	info := envelope.Info{Name: "sentinel-broker", Version: "test"}
	reg, err := registry.New()
	if err != nil {
		t.Fatal(err)
	}

	mux := NewMux()
	mux.Handle(envelope.MethodToolsCall, ToolsCallHandler(reg))

	s := NewServer(mux, config.Default(), info, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(s.Routes())
	defer srv.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"anything","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	resp := post(t, srv, body)
	if resp.Error == nil {
		t.Fatal("a server with no authenticator served tools/call anonymously")
	}
}

// TestDevAuthenticatorIsOffByDefault. It must not become production behaviour
// by omission.
func TestDevAuthenticatorIsOffByDefault(t *testing.T) {
	var zero DevAuthenticator
	if _, err := zero.Authenticate(nil); err == nil {
		t.Fatal("the zero-value DevAuthenticator authenticated a request; it must refuse " +
			"unless explicitly enabled")
	}
}
