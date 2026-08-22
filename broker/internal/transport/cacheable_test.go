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

	s := NewServer(mux, config.Default(), info, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
	resp := post(t, srv, body)

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
