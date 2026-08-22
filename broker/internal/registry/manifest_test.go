package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
)

// fakeTool is a fully-declared tool for exercising the registry. It declares
// all six properties because the registry refuses anything that does not.
type fakeTool struct {
	name    string
	desc    string
	in, out json.RawMessage
	scopes  []string
	rev     Reversibility
	cache   envelope.CachePolicy
	cap     int
}

func (f fakeTool) Name() string                      { return f.name }
func (f fakeTool) Description() string               { return f.desc }
func (f fakeTool) InputSchema() json.RawMessage      { return f.in }
func (f fakeTool) OutputSchema() json.RawMessage     { return f.out }
func (f fakeTool) Scopes() []string                  { return f.scopes }
func (f fakeTool) Reversibility() Reversibility      { return f.rev }
func (f fakeTool) CachePolicy() envelope.CachePolicy { return f.cache }
func (f fakeTool) TokenCap() int                     { return f.cap }
func (f fakeTool) Call(context.Context, Principal, json.RawMessage) (Result, error) {
	return &envelope.ToolsCallResult{}, nil
}

func tool(name string) fakeTool {
	return fakeTool{
		name:   name,
		desc:   "a tool named " + name,
		in:     json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}`),
		out:    json.RawMessage(`{"type":"object","properties":{"rows":{"type":"array"}}}`),
		scopes: []string{"warehouse:read"},
		rev:    Reversible,
		cache:  envelope.CachePolicy{TTLMs: 300_000, Scope: envelope.ScopePrivate},
		cap:    25_000,
	}
}

func mustRegistry(t *testing.T, tools ...Tool) *Registry {
	t.Helper()
	r, err := New(tools...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// TestToolsListByteStable is the §8.3 measurement, run as a test: 100 calls,
// hash each response body, assert exactly one distinct SHA-256.
func TestToolsListByteStable(t *testing.T) {
	r := mustRegistry(t, tool("warehouse.query"), tool("warehouse.describe"),
		tool("ops.deployment_plan"), tool("ops.deployment_apply"))

	seen := map[string]int{}
	for i := 0; i < 100; i++ {
		res, err := r.ToolsListResult(envelope.DefaultToolsListCachePolicy)
		if err != nil {
			t.Fatal(err)
		}
		envelope.Finalize(res, envelope.ResultComplete, envelope.Info{Name: "b", Version: "1"})
		body, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		seen[hex.EncodeToString(sum[:])]++
	}

	if len(seen) != 1 {
		t.Fatalf("100 tools/list calls produced %d distinct SHA-256 values, want exactly 1; "+
			"every downstream client's cache is invalidated by this", len(seen))
	}
}

// TestStableAcrossReload. Reload is where determinism usually dies, because a
// map got iterated somewhere and the registration order changed.
func TestStableAcrossReload(t *testing.T) {
	names := []string{"warehouse.query", "warehouse.describe", "ops.deployment_apply", "audit.search"}

	first := mustRegistry(t, tool(names[0]), tool(names[1]), tool(names[2]), tool(names[3])).ManifestHash()

	// Same tools, every registration order. A correct manifest does not care.
	orders := [][]int{
		{3, 2, 1, 0},
		{1, 3, 0, 2},
		{2, 0, 3, 1},
	}
	for _, order := range orders {
		tools := make([]Tool, 0, len(order))
		for _, i := range order {
			tools = append(tools, tool(names[i]))
		}
		if got := mustRegistry(t, tools...).ManifestHash(); got != first {
			t.Fatalf("registration order %v changed the manifest hash:\n got  %s\n want %s",
				order, got, first)
		}
	}
}

// TestSortIsBytewise: "Warehouse" vs "warehouse" proves the sort is not
// case-insensitive collation. Byte-wise, 'W' (0x57) precedes 'w' (0x77).
func TestSortIsBytewise(t *testing.T) {
	r := mustRegistry(t, tool("warehouse.query"), tool("Warehouse.query"), tool("ops.apply"))

	var descriptors []envelope.ToolDescriptor
	if err := json.Unmarshal(r.ManifestBytes(), &descriptors); err != nil {
		t.Fatal(err)
	}

	got := make([]string, 0, len(descriptors))
	for _, d := range descriptors {
		got = append(got, d.Name)
	}
	want := []string{"Warehouse.query", "ops.apply", "warehouse.query"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v — the sort must be bytes.Compare, not locale collation "+
			"or case-insensitive", got, want)
	}
}

// TestRequiredAndEnumArraysAreSorted. §8.3 step 3: their order carries no
// meaning but does change the hash, so two servers describing the same schema
// must produce the same bytes.
func TestRequiredAndEnumArraysAreSorted(t *testing.T) {
	a := tool("t.one")
	a.in = json.RawMessage(`{"type":"object","required":["zulu","alpha"],"properties":{"mode":{"enum":["z","a","m"]}}}`)

	b := tool("t.one")
	b.in = json.RawMessage(`{"type":"object","required":["alpha","zulu"],"properties":{"mode":{"enum":["a","m","z"]}}}`)

	if ha, hb := mustRegistry(t, a).ManifestHash(), mustRegistry(t, b).ManifestHash(); ha != hb {
		t.Fatalf("the same schema written with differently-ordered required/enum arrays hashed "+
			"differently:\n %s\n %s", ha, hb)
	}
}

// TestManifestHashChangesWhenAToolChanges. The flip side: the hash must be
// sensitive to real change, or it is not a cache key.
func TestManifestHashChangesWhenAToolChanges(t *testing.T) {
	base := mustRegistry(t, tool("warehouse.query")).ManifestHash()

	changed := tool("warehouse.query")
	changed.desc = "a materially different description"

	if got := mustRegistry(t, changed).ManifestHash(); got == base {
		t.Fatal("changing a tool's description did not change the manifest hash")
	}
}

func TestManifestHashIsPrefixed(t *testing.T) {
	h := mustRegistry(t, tool("a.b")).ManifestHash()
	if !strings.HasPrefix(h, "sha256:") {
		t.Fatalf("hash = %q, want a sha256: prefix", h)
	}
	if len(h) != len("sha256:")+64 {
		t.Fatalf("hash = %q, want 64 hex characters after the prefix", h)
	}
}

func TestManifestHasNoInsignificantWhitespace(t *testing.T) {
	a := tool("t.one")
	a.in = json.RawMessage("{\n  \"type\" : \"object\"\n}")
	m := mustRegistry(t, a).ManifestBytes()

	if strings.ContainsAny(string(m), "\n\t") {
		t.Fatalf("manifest contains insignificant whitespace: %s", m)
	}
}

// TestServesPrecomputedBytes. §9.2: tools/list serves the precomputed bytes,
// because re-serializing per request is where determinism dies. What a client
// receives must be byte-identical to what was hashed.
func TestServedDescriptorsMatchTheHashedManifest(t *testing.T) {
	r := mustRegistry(t, tool("warehouse.query"), tool("ops.apply"))

	res, err := r.ToolsListResult(envelope.DefaultToolsListCachePolicy)
	if err != nil {
		t.Fatal(err)
	}
	served, err := json.Marshal(res.Tools)
	if err != nil {
		t.Fatal(err)
	}
	if string(served) != string(r.ManifestBytes()) {
		t.Fatalf("what the client receives is not what was hashed:\n served %s\n hashed %s",
			served, r.ManifestBytes())
	}
	if res.ManifestHash != r.ManifestHash() {
		t.Fatalf("result carries hash %q, registry computed %q", res.ManifestHash, r.ManifestHash())
	}
}

func TestCacheableFieldsPresentOnToolsList(t *testing.T) {
	r := mustRegistry(t, tool("a.b"))
	res, err := r.ToolsListResult(envelope.DefaultToolsListCachePolicy)
	if err != nil {
		t.Fatal(err)
	}
	if res.TTLMs == 0 {
		t.Error("tools/list is a CacheableResult and must carry ttlMs")
	}
	if res.CacheScope != envelope.ScopePrivate {
		t.Errorf("cacheScope = %q, want private: the visible tool set varies by the "+
			"principal's scopes, and a shared intermediary must not serve one tenant's "+
			"tool list to another", res.CacheScope)
	}
}
