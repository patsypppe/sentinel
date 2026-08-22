package envelope

import "testing"

// TestNoErrorInReservedRange enumerates every error code this server can emit
// and asserts none falls inside -32020…-32099, which docs/HANDOFF.md §7.2
// reserves for the specification. The three codes the spec itself defines in
// that range are the only permitted occupants.
func TestNoErrorInReservedRange(t *testing.T) {
	specAllocated := map[int]bool{
		CodeHeaderMismatch:                  true,
		CodeMissingRequiredClientCapability: true,
		CodeUnsupportedProtocolVersion:      true,
	}

	for _, code := range AllCodes() {
		if !IsSpecReserved(code) {
			continue
		}
		if !specAllocated[code] {
			t.Errorf("code %d is inside the reserved range -32020…-32099 but is not one of "+
				"the three the specification defines; implementation codes belong in -32000…-32019", code)
		}
	}
}

// TestImplementationCodesAreInTheirOwnRange: the flip side. Sentinel's own codes
// must live in -32000…-32019, not scattered through the JSON-RPC space.
func TestImplementationCodesAreInTheirOwnRange(t *testing.T) {
	for _, code := range ImplementationCodes() {
		if code > -32000 || code < -32019 {
			t.Errorf("implementation code %d is outside -32000…-32019", code)
		}
	}
}

func TestReservedRangeBoundaries(t *testing.T) {
	cases := []struct {
		code int
		want bool
	}{
		{-32019, false}, // last implementation-defined code
		{-32020, true},  // first reserved code
		{-32099, true},  // last reserved code
		{-32100, false},
		{-32602, false}, // pre-dates the partition; standard JSON-RPC
		{-32601, false},
	}
	for _, c := range cases {
		if got := IsSpecReserved(c.code); got != c.want {
			t.Errorf("IsSpecReserved(%d) = %v, want %v", c.code, got, c.want)
		}
	}
}

// TestResourceNotFoundIsInvalidParams: the 2026-07-28 revision moved resource
// not found from -32002 to -32602. A server still emitting -32002 for it is
// non-conformant, and this is one of the seeded violations in the fixture.
func TestResourceNotFoundIsInvalidParams(t *testing.T) {
	err := ErrResourceNotFound("file:///nope")
	if err.Code != CodeInvalidParams {
		t.Fatalf("resource-not-found code = %d, want %d (-32002 was the pre-2026-07-28 code)",
			err.Code, CodeInvalidParams)
	}
}

// TestMinus32002IsDeliberatelyUnallocated. -32002 is inside our own permitted
// range, so allocating it would be legal — but it was resource-not-found in the
// previous revision, and reusing it makes error triage ambiguous for exactly the
// clients most likely to be mid-migration.
func TestMinus32002IsDeliberatelyUnallocated(t *testing.T) {
	for _, code := range ImplementationCodes() {
		if code == -32002 {
			t.Fatal("-32002 must stay unallocated: it was resource-not-found before this revision")
		}
	}
}

// TestEveryCodeHasAName: an error code with no name is an error code nobody can
// triage, and the conformance report prints the name next to the citation.
func TestEveryCodeHasAName(t *testing.T) {
	for _, code := range AllCodes() {
		if CodeName(code) == "" {
			t.Errorf("code %d has no name", code)
		}
	}
}

// TestErrorsAreDistinct guards against a copy-paste that gives two conditions
// the same code, which would make them indistinguishable to a client.
func TestErrorsAreDistinct(t *testing.T) {
	seen := map[int]bool{}
	for _, code := range AllCodes() {
		if seen[code] {
			t.Errorf("code %d is allocated twice", code)
		}
		seen[code] = true
	}
}
