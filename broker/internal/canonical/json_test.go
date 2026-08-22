package canonical

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestObjectKeysAreSorted(t *testing.T) {
	got, err := Bytes(json.RawMessage(`{"zebra":1,"apple":2,"Mango":3}`))
	if err != nil {
		t.Fatal(err)
	}
	// Byte-wise: uppercase M (0x4D) sorts before lowercase a (0x61) and z.
	want := `{"Mango":3,"apple":2,"zebra":1}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestSortIsBytewiseNotCaseInsensitive(t *testing.T) {
	got, err := Bytes(json.RawMessage(`{"warehouse":1,"Warehouse":2}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"Warehouse":2,"warehouse":1}`
	if string(got) != want {
		t.Fatalf("case-insensitive collation leaked in:\ngot  %s\nwant %s", got, want)
	}
}

func TestOutputIsStableAcrossRepeatedCalls(t *testing.T) {
	// The failure this catches is map iteration order leaking into output. Go
	// randomizes it per range, so a single comparison is not enough.
	in := json.RawMessage(`{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8}`)
	first, err := Bytes(in)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		again, err := Bytes(in)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatalf("iteration %d differed:\n%s\n%s", i, first, again)
		}
	}
}

func TestWhitespaceIsInsignificant(t *testing.T) {
	spaced, err := Bytes(json.RawMessage("{\n  \"a\" : 1,\n  \"b\": [ 1, 2 ]\n}"))
	if err != nil {
		t.Fatal(err)
	}
	tight, err := Bytes(json.RawMessage(`{"a":1,"b":[1,2]}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(spaced) != string(tight) {
		t.Fatalf("whitespace changed the output:\n%s\n%s", spaced, tight)
	}
}

// TestNumberTokensSurviveVerbatim is the §14 gotcha 2 guard. A large integer
// round-tripped through float64 loses its low digits, and a hash computed over
// the result is silently wrong.
func TestNumberTokensSurviveVerbatim(t *testing.T) {
	cases := []string{
		`{"n":9007199254740993}`, // 2^53+1: not representable as float64
		`{"n":1e3}`,
		`{"n":1.50}`,
		`{"n":-0}`,
	}
	for _, in := range cases {
		got, err := Bytes(json.RawMessage(in))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if string(got) != in {
			t.Errorf("number token was reinterpreted:\ngot  %s\nwant %s", got, in)
		}
	}
}

func TestStrictRejectsFloats(t *testing.T) {
	_, err := Strict(json.RawMessage(`{"duration":1.5}`))
	if !errors.Is(err, ErrFloatNotPermitted) {
		t.Fatalf("err = %v, want ErrFloatNotPermitted: durations are integer milliseconds", err)
	}
}

func TestStrictAllowsIntegers(t *testing.T) {
	if _, err := Strict(json.RawMessage(`{"durationMs":1500}`)); err != nil {
		t.Fatalf("integers must be permitted: %v", err)
	}
}

// TestArrayOrderIsPreservedByDefault. Order is meaningful in JSON arrays;
// sorting is opt-in per key.
func TestArrayOrderIsPreservedByDefault(t *testing.T) {
	got, err := Bytes(json.RawMessage(`{"steps":["c","a","b"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"steps":["c","a","b"]}` {
		t.Fatalf("array order was changed: %s", got)
	}
}

func TestNamedArrayKeysAreSorted(t *testing.T) {
	opts := Options{SortArrayKeys: map[string]bool{"required": true, "enum": true}}

	got, err := With(json.RawMessage(`{"required":["b","a"],"enum":["z","y"],"steps":["c","a"]}`), opts)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"enum":["y","z"],"required":["a","b"],"steps":["c","a"]}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestNestedObjectsAreCanonicalized(t *testing.T) {
	got, err := Bytes(json.RawMessage(`{"outer":{"z":1,"a":{"y":2,"b":3}}}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"outer":{"a":{"b":3,"y":2},"z":1}}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
