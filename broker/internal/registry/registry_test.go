package registry

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
)

// TestToolMustDeclareAllSixProperties. §7.3: enforced in the interface, not in
// a review checklist. Each case removes exactly one declaration.
func TestToolMustDeclareAllSixProperties(t *testing.T) {
	cases := []struct {
		desc     string
		mutate   func(*fakeTool)
		wantHint string
	}{
		{"no description", func(f *fakeTool) { f.desc = "" }, "description"},
		{"no input schema", func(f *fakeTool) { f.in = nil }, "input schema"},
		{"no output schema", func(f *fakeTool) { f.out = nil }, "output schema"},
		{"nil scopes", func(f *fakeTool) { f.scopes = nil }, "scopes"},
		{"no reversibility", func(f *fakeTool) { f.rev = "" }, "reversibility"},
		{"no token cap", func(f *fakeTool) { f.cap = 0 }, "token cap"},
		{"no cache scope", func(f *fakeTool) { f.cache = envelope.CachePolicy{TTLMs: 1} }, "cacheScope"},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			f := tool("warehouse.query")
			c.mutate(&f)

			_, err := New(f)
			if err == nil {
				t.Fatalf("a tool with %s was registered; the six properties are mandatory", c.desc)
			}
			if !strings.Contains(err.Error(), c.wantHint) {
				t.Fatalf("error %q does not mention %q", err, c.wantHint)
			}
		})
	}
}

// TestEmptyScopesIsDifferentFromNilScopes. An explicitly empty slice is a
// decision ("no scope required"); nil is the absence of one.
func TestEmptyScopesIsDifferentFromNilScopes(t *testing.T) {
	f := tool("public.thing")
	f.scopes = []string{}
	if _, err := New(f); err != nil {
		t.Fatalf("an explicitly empty scope list is a valid declaration: %v", err)
	}
}

func TestDuplicateRegistrationIsRejected(t *testing.T) {
	if _, err := New(tool("a.b"), tool("a.b")); err == nil {
		t.Fatal("registering the same tool name twice must be rejected")
	}
}

// TestReversibilityDrivesConfirmation. §7.3: Irreversible always confirms;
// Recoverable confirms above a threshold; Reversible never does. Putting it in
// the type system means a new tool cannot skip the question.
func TestReversibilityDrivesConfirmation(t *testing.T) {
	cases := []struct {
		rev            Reversibility
		aboveThreshold bool
		wantConfirm    bool
	}{
		{Reversible, false, false},
		{Reversible, true, false},
		{Recoverable, false, false},
		{Recoverable, true, true},
		{Irreversible, false, true},
		{Irreversible, true, true},
	}
	for _, c := range cases {
		if got := c.rev.RequiresConfirmation(c.aboveThreshold); got != c.wantConfirm {
			t.Errorf("%s(above=%v).RequiresConfirmation() = %v, want %v",
				c.rev, c.aboveThreshold, got, c.wantConfirm)
		}
	}
}

// TestIrreversibleAlwaysConfirms, called out separately because it is the
// property ops.deployment_apply depends on and the one worth a loud failure.
func TestIrreversibleAlwaysConfirms(t *testing.T) {
	if !Irreversible.RequiresConfirmation(false) {
		t.Fatal("an irreversible tool must require MRTR confirmation with no threshold and no exception")
	}
}

func TestPrincipalScopeMatchIsExact(t *testing.T) {
	p := Principal{Scopes: []string{"warehouse:read"}}

	if !p.HasScope("warehouse:read") {
		t.Fatal("an exact scope must match")
	}
	if p.HasScope("warehouse") {
		t.Fatal("a prefix must not match: scope checks are exact membership")
	}
	if p.HasScope("warehouse:read:extra") {
		t.Fatal("a longer scope must not match")
	}
}

func TestTokenCountIsReportedWithItsTokenizer(t *testing.T) {
	r := mustRegistry(t, tool("warehouse.query"), tool("ops.apply"))
	tc := r.Tokens()

	if tc.Tokenizer != TokenizerName {
		t.Fatalf("tokenizer = %q, want %q: a number without a stated method is not a measurement",
			tc.Tokenizer, TokenizerName)
	}
	if tc.Manifest <= 0 {
		t.Fatal("manifest token count must be positive")
	}
	if len(tc.PerTool) != 2 {
		t.Fatalf("per-tool counts = %d, want 2", len(tc.PerTool))
	}
}

func TestTokenEstimateGrowsWithContent(t *testing.T) {
	small := EstimateTokens([]byte(`{"a":1}`))
	large := EstimateTokens([]byte(`{"a":1,"description":"a much longer description with many words in it"}`))
	if large <= small {
		t.Fatalf("estimate did not grow with content: %d vs %d", small, large)
	}
}

func TestTokenEstimateIsDeterministic(t *testing.T) {
	in := []byte(`{"name":"warehouse.query","description":"run a scoped query"}`)
	first := EstimateTokens(in)
	for i := 0; i < 50; i++ {
		if got := EstimateTokens(in); got != first {
			t.Fatalf("estimate varied: %d then %d", first, got)
		}
	}
}

func TestLookupFindsRegisteredTools(t *testing.T) {
	r := mustRegistry(t, tool("warehouse.query"))
	if _, ok := r.Lookup("warehouse.query"); !ok {
		t.Fatal("a registered tool must be found")
	}
	if _, ok := r.Lookup("nope"); ok {
		t.Fatal("an unregistered tool must not be found")
	}
}

func TestDescriptorsAreInCanonicalOrder(t *testing.T) {
	r := mustRegistry(t, tool("z.tool"), tool("a.tool"), tool("m.tool"))
	d := r.Descriptors()
	if len(d) != 3 {
		t.Fatalf("got %d descriptors, want 3", len(d))
	}
	if d[0].Name != "a.tool" || d[1].Name != "m.tool" || d[2].Name != "z.tool" {
		t.Fatalf("descriptors are not in canonical order: %v", []string{d[0].Name, d[1].Name, d[2].Name})
	}
}

func TestSchemasAreCanonicalizedInTheManifest(t *testing.T) {
	f := tool("t.one")
	f.in = json.RawMessage(`{"properties":{"b":{"type":"string"},"a":{"type":"number"}},"type":"object"}`)

	r := mustRegistry(t, f)
	var descriptors []envelope.ToolDescriptor
	if err := json.Unmarshal(r.ManifestBytes(), &descriptors); err != nil {
		t.Fatal(err)
	}
	got := string(descriptors[0].InputSchema)
	want := `{"properties":{"a":{"type":"number"},"b":{"type":"string"}},"type":"object"}`
	if got != want {
		t.Fatalf("schema was not canonicalized:\n got  %s\n want %s", got, want)
	}
}
