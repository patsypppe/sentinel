package mrtr

import (
	"encoding/json"
	"testing"
)

// TestArgumentsHashIgnoresSerializationDifferences.
//
// A client that re-serializes between the original call and the retry may emit
// the same value with different bytes. Rejecting that would fail an honest
// client, so the hash is computed over the canonical form.
func TestArgumentsHashIgnoresSerializationDifferences(t *testing.T) {
	same := []json.RawMessage{
		json.RawMessage(`{"plan":"hnd_ABC","force":false}`),
		json.RawMessage(`{"force":false,"plan":"hnd_ABC"}`),
		json.RawMessage("{\n  \"plan\" : \"hnd_ABC\",\n  \"force\": false\n}"),
	}

	first, err := ArgumentsHash(same[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range same[1:] {
		got, err := ArgumentsHash(args)
		if err != nil {
			t.Fatal(err)
		}
		if got != first {
			t.Fatalf("the same arguments serialized differently hashed differently:\n %s\n %s",
				first, got)
		}
	}
}

// TestArgumentsHashDetectsRealChanges. The flip side: the hash must be
// sensitive to anything that changes what was approved.
func TestArgumentsHashDetectsRealChanges(t *testing.T) {
	base := json.RawMessage(`{"plan":"hnd_ABC","force":false}`)
	baseHash, err := ArgumentsHash(base)
	if err != nil {
		t.Fatal(err)
	}

	changed := []json.RawMessage{
		json.RawMessage(`{"plan":"hnd_XYZ","force":false}`),           // different target
		json.RawMessage(`{"plan":"hnd_ABC","force":true}`),            // different flag
		json.RawMessage(`{"plan":"hnd_ABC"}`),                         // a field removed
		json.RawMessage(`{"plan":"hnd_ABC","force":false,"extra":1}`), // one added
	}
	for _, args := range changed {
		got, err := ArgumentsHash(args)
		if err != nil {
			t.Fatal(err)
		}
		if got == baseHash {
			t.Errorf("mutated arguments %s hashed the same as the original", args)
		}
	}
}

func TestEmptyAndAbsentArgumentsHashAlike(t *testing.T) {
	absent, err := ArgumentsHash(nil)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := ArgumentsHash(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if absent != empty {
		t.Fatal("absent and empty arguments must hash alike, or a client that omits an " +
			"empty object on retry is rejected for nothing")
	}
}

func TestArgumentsMatch(t *testing.T) {
	original := json.RawMessage(`{"plan":"hnd_ABC"}`)
	h, err := ArgumentsHash(original)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := ArgumentsMatch(h, json.RawMessage(`{"plan":"hnd_ABC"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("identical arguments must match")
	}

	ok, err = ArgumentsMatch(h, json.RawMessage(`{"plan":"hnd_OTHER"}`))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("different arguments must not match")
	}
}

func TestArgumentsHashIsPrefixed(t *testing.T) {
	h, err := ArgumentsHash(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != len("sha256:")+64 || h[:7] != "sha256:" {
		t.Fatalf("hash = %q, want sha256: plus 64 hex characters", h)
	}
}
