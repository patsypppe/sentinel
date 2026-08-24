package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func record() Record {
	return Record{
		OccurredAt:        time.Unix(1_756_000_000, 0).UTC(),
		TenantID:          "00000000-0000-0000-0000-000000000001",
		PrincipalID:       "00000000-0000-0000-0000-0000000000a1",
		ToolName:          "warehouse.query",
		ScopesExercised:   []string{"warehouse:read"},
		ArgumentsRedacted: json.RawMessage(`{"sql":"SELECT 1"}`),
		ProtocolVersion:   "2026-07-28",
		TraceID:           "00-abc-def-01",
		Outcome:           OutcomeOK,
		DurationMs:        42,
	}
}

func TestRowHashIsDeterministic(t *testing.T) {
	first, err := RowHash(GenesisHash, record())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		again, err := RowHash(GenesisHash, record())
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatalf("hash varied between calls:\n %s\n %s", first, again)
		}
	}
}

// TestScopeOrderDoesNotChangeTheHash. Scopes are a set; their order carries no
// meaning but would change the hash, so it is fixed rather than left to
// whatever produced them.
func TestScopeOrderDoesNotChangeTheHash(t *testing.T) {
	a, b := record(), record()
	a.ScopesExercised = []string{"warehouse:read", "warehouse:describe"}
	b.ScopesExercised = []string{"warehouse:describe", "warehouse:read"}

	ha, err := RowHash(GenesisHash, a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := RowHash(GenesisHash, b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatal("the same scope set in a different order hashed differently")
	}
}

// TestArgumentSerializationDoesNotChangeTheHash. Same value, different bytes.
func TestArgumentSerializationDoesNotChangeTheHash(t *testing.T) {
	a, b := record(), record()
	a.ArgumentsRedacted = json.RawMessage(`{"limit":10,"sql":"SELECT 1"}`)
	b.ArgumentsRedacted = json.RawMessage("{\n  \"sql\" : \"SELECT 1\",\n  \"limit\": 10\n}")

	ha, _ := RowHash(GenesisHash, a)
	hb, _ := RowHash(GenesisHash, b)
	if ha != hb {
		t.Fatal("the same arguments serialized differently hashed differently")
	}
}

// TestEveryFieldIsCovered. A field that does not affect the hash is a field an
// attacker can rewrite freely, which is worse than not recording it at all.
func TestEveryFieldIsCovered(t *testing.T) {
	base, err := RowHash(GenesisHash, record())
	if err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*Record){
		"tenant":      func(r *Record) { r.TenantID = "00000000-0000-0000-0000-00000000000f" },
		"principal":   func(r *Record) { r.PrincipalID = "00000000-0000-0000-0000-0000000000ff" },
		"tool":        func(r *Record) { r.ToolName = "ops.deployment_apply" },
		"scopes":      func(r *Record) { r.ScopesExercised = []string{"ops:apply"} },
		"arguments":   func(r *Record) { r.ArgumentsRedacted = json.RawMessage(`{"sql":"DROP TABLE x"}`) },
		"protocol":    func(r *Record) { r.ProtocolVersion = "2025-11-25" },
		"trace":       func(r *Record) { r.TraceID = "00-999-999-01" },
		"correlation": func(r *Record) { r.CorrelationID = "mrtr_x" },
		"outcome":     func(r *Record) { r.Outcome = OutcomeDenied },
		"errorCode":   func(r *Record) { r.ErrorCode = 1000 },
		"duration":    func(r *Record) { r.DurationMs = 43 },
		"occurredAt":  func(r *Record) { r.OccurredAt = r.OccurredAt.Add(time.Second) },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := record()
			mutate(&r)
			got, err := RowHash(GenesisHash, r)
			if err != nil {
				t.Fatal(err)
			}
			if got == base {
				t.Fatalf("changing %s did not change the hash; that field can be rewritten "+
					"freely, which is worse than not recording it", name)
			}
		})
	}
}

// TestPrevHashIsMixedIn. Without it the rows would each be self-consistent but
// unordered, and a row could be moved or removed undetectably.
func TestPrevHashIsMixedIn(t *testing.T) {
	a, err := RowHash(GenesisHash, record())
	if err != nil {
		t.Fatal(err)
	}
	b, err := RowHash(strings.Repeat("f", 64), record())
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("the previous hash does not affect the row hash; rows would be reorderable")
	}
}

func TestRowHashRejectsAMalformedPrevious(t *testing.T) {
	for _, prev := range []string{"", "abc", strings.Repeat("z", 64), strings.Repeat("a", 63)} {
		if _, err := RowHash(prev, record()); err == nil {
			t.Errorf("prev hash %q was accepted", prev)
		}
	}
}

// TestFloatsAreRejectedInHashedFields. §8.7: durations are integer
// milliseconds. Languages disagree on how to print a float, and a hash that
// depends on that is not portable across the languages that might verify it.
func TestFloatsAreRejectedInHashedFields(t *testing.T) {
	r := record()
	r.ArgumentsRedacted = json.RawMessage(`{"threshold":1.5}`)

	if _, err := r.CanonicalJSON(); err == nil {
		t.Fatal("a float in the hashed fields was accepted")
	}
}

func TestCanonicalJSONHasNoInsignificantWhitespace(t *testing.T) {
	body, err := record().CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(string(body), "\n\t") {
		t.Fatalf("canonical form contains insignificant whitespace: %s", body)
	}
}

func TestCanonicalJSONSortsKeys(t *testing.T) {
	body, err := record().CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		t.Fatal(err)
	}

	// Keys must appear in sorted order in the raw bytes, not merely be present.
	last := ""
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if _, err := decoder.Token(); err != nil { // opening brace
		t.Fatal(err)
	}
	for decoder.More() {
		tok, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		key, ok := tok.(string)
		if !ok {
			t.Fatalf("expected a key, got %v", tok)
		}
		if key < last {
			t.Fatalf("keys are not sorted: %q came after %q", key, last)
		}
		last = key
		var discard json.RawMessage
		if err := decoder.Decode(&discard); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGenesisHashIsSixtyFourZeros(t *testing.T) {
	if len(GenesisHash) != 64 || strings.Trim(GenesisHash, "0") != "" {
		t.Fatalf("GenesisHash = %q, want 64 zeros", GenesisHash)
	}
}

// --- redaction -------------------------------------------------------------

func TestRedactRemovesSensitiveValues(t *testing.T) {
	args := json.RawMessage(`{
      "sql": "SELECT 1",
      "password": "hunter2",
      "nested": {"api_key": "sk-live-abc", "limit": 10},
      "list": [{"token": "t-1"}, {"safe": "yes"}]
    }`)

	rendered := string(Redact(args))

	for _, secret := range []string{"hunter2", "sk-live-abc", "t-1"} {
		if strings.Contains(rendered, secret) {
			t.Errorf("%q survived redaction: %s", secret, rendered)
		}
	}
	// Structure is preserved, so the row still shows the SHAPE of the call.
	for _, kept := range []string{"SELECT 1", "limit", "10", "safe", "password", "api_key"} {
		if !strings.Contains(rendered, kept) {
			t.Errorf("%q was lost; redaction must preserve structure: %s", kept, rendered)
		}
	}
}

func TestRedactIsCaseInsensitiveOnKeys(t *testing.T) {
	out := Redact(json.RawMessage(`{"Password":"hunter2","API_KEY":"sk-live"}`))
	if strings.Contains(string(out), "hunter2") || strings.Contains(string(out), "sk-live") {
		t.Fatalf("case-varied keys were not redacted: %s", out)
	}
}

func TestRedactIsDeterministic(t *testing.T) {
	args := json.RawMessage(`{"z":1,"a":2,"password":"x","m":{"q":3,"b":4}}`)

	first := Redact(args)
	for i := 0; i < 100; i++ {
		again := Redact(args)
		if string(again) != string(first) {
			t.Fatalf("redaction varied between calls, so the same call would hash "+
				"differently each time:\n %s\n %s", first, again)
		}
	}
}

func TestRedactHandlesEmptyArguments(t *testing.T) {
	out := Redact(nil)
	if string(out) != "{}" {
		t.Fatalf("Redact(nil) = %s, want {}", out)
	}
}
