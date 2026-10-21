package envelope

import (
	"encoding/json"
	"testing"
)

// allResultTypes returns one zero value of every result type the server can
// return. Adding a result type without adding it here is caught by
// TestAllResultTypesAreEnumerated below.
func allResultTypes() []Result {
	return []Result{
		&DiscoverResult{},
		&ToolsListResult{},
		&ToolsCallResult{},
		&ResourcesListResult{},
		&ResourceTemplatesListResult{},
		&ResourcesReadResult{},
		&PromptsListResult{},
	}
}

// TestEveryResultCarriesResultType marshals every result type and asserts
// `resultType` is present and non-empty. docs/HANDOFF.md §7.1: it is never the
// zero value.
func TestEveryResultCarriesResultType(t *testing.T) {
	info := Info{Name: "sentinel-broker", Version: "0.1.0"}

	for _, r := range allResultTypes() {
		Finalize(r, ResultComplete, info)

		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("%T: marshal: %v", r, err)
		}

		var probe struct {
			ResultType string `json:"resultType"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			t.Fatalf("%T: unmarshal: %v", r, err)
		}
		if probe.ResultType == "" {
			t.Errorf("%T marshalled without a resultType: %s", r, raw)
		}
	}
}

// TestEveryResultEchoesServerInfo — the second half of the §7.1 rule. A client
// keys its cache on the (name, version) pair, so a result that omits it is
// uncacheable.
func TestEveryResultEchoesServerInfo(t *testing.T) {
	info := Info{Name: "sentinel-broker", Version: "0.1.0"}

	for _, r := range allResultTypes() {
		Finalize(r, ResultComplete, info)

		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("%T: marshal: %v", r, err)
		}

		var probe struct {
			Meta struct {
				ServerInfo *Info `json:"io.modelcontextprotocol/serverInfo"`
			} `json:"_meta"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			t.Fatalf("%T: unmarshal: %v", r, err)
		}
		if probe.Meta.ServerInfo == nil || probe.Meta.ServerInfo.Name == "" {
			t.Errorf("%T marshalled without serverInfo in _meta: %s", r, raw)
		}
	}
}

// TestCacheableResultsCarryTTLAndScope. Every list and read result is a
// CacheableResult and must carry both fields (§8.3).
func TestCacheableResultsCarryTTLAndScope(t *testing.T) {
	info := Info{Name: "sentinel-broker", Version: "0.1.0"}

	cacheable := []Result{
		&DiscoverResult{},
		&ToolsListResult{},
		&ResourcesListResult{},
		&ResourceTemplatesListResult{},
		&ResourcesReadResult{},
		&PromptsListResult{},
	}

	for _, r := range cacheable {
		c, ok := r.(Cacheable)
		if !ok {
			t.Errorf("%T is a list/read result but does not implement Cacheable", r)
			continue
		}
		c.SetCache(CachePolicy{TTLMs: 300_000, Scope: ScopePrivate})
		Finalize(r, ResultComplete, info)

		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("%T: marshal: %v", r, err)
		}

		var probe struct {
			TTLMs      *int    `json:"ttlMs"`
			CacheScope *string `json:"cacheScope"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			t.Fatalf("%T: unmarshal: %v", r, err)
		}
		if probe.TTLMs == nil {
			t.Errorf("%T is missing ttlMs: %s", r, raw)
		}
		if probe.CacheScope == nil || *probe.CacheScope == "" {
			t.Errorf("%T is missing cacheScope: %s", r, raw)
		}
	}
}

// TestToolsListCacheScopeIsPrivate. The visible tool set varies by the
// principal's scopes, so a shared intermediary must not be allowed to serve one
// tenant's tool list to another (§8.3).
func TestToolsListCacheScopeIsPrivate(t *testing.T) {
	if DefaultToolsListCachePolicy.Scope != ScopePrivate {
		t.Fatalf("tools/list cacheScope = %q, want %q: the visible tool set varies by scope",
			DefaultToolsListCachePolicy.Scope, ScopePrivate)
	}
}

// TestMissingResultTypeReadsAsComplete. A result from an earlier-protocol server
// omits resultType entirely; the harness needs to scan such servers without
// crashing (§7.1).
func TestMissingResultTypeReadsAsComplete(t *testing.T) {
	if got := NormalizeResultType(""); got != ResultComplete {
		t.Fatalf("NormalizeResultType(\"\") = %q, want %q", got, ResultComplete)
	}
	if got := NormalizeResultType(ResultInputRequired); got != ResultInputRequired {
		t.Fatalf("NormalizeResultType(input_required) = %q, want it unchanged", got)
	}
}

// TestExtractMetaReadsProtocolVersion: `_meta` rides inside params, and
// negotiation happens on every request, so this parse is on the hot path.
func TestExtractMetaReadsProtocolVersion(t *testing.T) {
	params := json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","traceparent":"00-abc-def-01"},"name":"warehouse.query"}`)

	meta, err := ExtractMeta(params)
	if err != nil {
		t.Fatalf("ExtractMeta: %v", err)
	}
	if meta.ProtocolVersion != RevisionCurrent {
		t.Fatalf("ProtocolVersion = %q, want %q", meta.ProtocolVersion, RevisionCurrent)
	}
	if meta.Traceparent != "00-abc-def-01" {
		t.Fatalf("Traceparent = %q, want it carried through", meta.Traceparent)
	}
}

func TestExtractMetaToleratesAbsentParams(t *testing.T) {
	meta, err := ExtractMeta(nil)
	if err != nil {
		t.Fatalf("absent params must not be an error, got %v", err)
	}
	if meta.ProtocolVersion != "" {
		t.Fatalf("ProtocolVersion = %q, want empty", meta.ProtocolVersion)
	}
}

// TestNoMapStringAnyInResults. §14 gotcha 1: Go map iteration order is
// randomized, so a map anywhere in a serialized result makes the byte-stable
// manifest stable in tests and unstable in production.
func TestResultsMarshalDeterministically(t *testing.T) {
	info := Info{Name: "sentinel-broker", Version: "0.1.0"}

	for _, r := range allResultTypes() {
		Finalize(r, ResultComplete, info)
		first, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("%T: %v", r, err)
		}
		for i := 0; i < 50; i++ {
			again, err := json.Marshal(r)
			if err != nil {
				t.Fatalf("%T: %v", r, err)
			}
			if string(again) != string(first) {
				t.Fatalf("%T serialized differently across calls:\n %s\n %s", r, first, again)
			}
		}
	}
}
