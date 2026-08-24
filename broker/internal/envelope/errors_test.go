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
				"the three the specification defines; implementation codes belong in 1000…1019", code)
		}
	}
}

// TestNoCodeInJSONRPCReservedRange. The specification says new codes SHOULD be
// allocated outside -32768…-32000 entirely. The three codes the spec itself
// defines are the only ones of ours inside it, and they are not ours.
func TestNoCodeInJSONRPCReservedRange(t *testing.T) {
	specDefined := map[int]bool{
		CodeHeaderMismatch:                  true,
		CodeMissingRequiredClientCapability: true,
		CodeUnsupportedProtocolVersion:      true,
		CodeParseError:                      true,
		CodeInvalidRequest:                  true,
		CodeMethodNotFound:                  true,
		CodeInvalidParams:                   true,
		CodeInternalError:                   true,
	}
	for _, code := range AllCodes() {
		if specDefined[code] {
			continue
		}
		if IsJSONRPCReserved(code) {
			t.Errorf("code %d is inside the JSON-RPC reserved range -32768…-32000; "+
				"new codes belong outside it", code)
		}
	}
}

// TestNoCodeInLegacySubRange. -32000…-32019 is the sub-range the revision
// retired: "new implementations SHOULD NOT use codes from this sub-range at all".
func TestNoCodeInLegacySubRange(t *testing.T) {
	for _, code := range AllCodes() {
		if IsLegacySubRange(code) {
			t.Errorf("code %d is in the retired legacy sub-range -32000…-32019", code)
		}
	}
}

func TestImplementationCodesArePositive(t *testing.T) {
	for _, code := range ImplementationCodes() {
		if code < 1000 || code > 1019 {
			t.Errorf("implementation code %d is outside the allocated block 1000…1019", code)
		}
	}
}

// TestLegacyCodeMapsEveryMigratedCode. A client mid-migration triages on the old
// number; every code we moved must be able to say what it used to be.
func TestLegacyCodeMapsEveryMigratedCode(t *testing.T) {
	for _, code := range ImplementationCodes() {
		old, ok := LegacyCode(code)
		if !ok {
			t.Errorf("code %d has no recorded legacy predecessor", code)
			continue
		}
		if !IsLegacySubRange(old) {
			t.Errorf("legacy predecessor %d of %d is not in -32000…-32019", old, code)
		}
	}
}

func TestReservedRangeBoundaries(t *testing.T) {
	cases := []struct {
		code int
		want bool
	}{
		{-32019, false}, // last code in the retired legacy sub-range
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

// TestOneThousandTwoIsDeliberatelyUnallocated mirrors the old
// TestMinus32002IsDeliberatelyUnallocated: 1002 is skipped because -32002 was,
// and keeping the ordinal gap keeps triage knowledge transferable.
func TestOneThousandTwoIsDeliberatelyUnallocated(t *testing.T) {
	for _, code := range AllCodes() {
		if code == 1002 {
			t.Fatal("1002 must stay unallocated: it mirrors -32002, which was " +
				"resource-not-found before this revision")
		}
	}
}

func TestWithLegacyCodeAttachesTheOldNumber(t *testing.T) {
	err := WithLegacyCode(New(CodeHandleNotResolvable, "nope", nil))
	data, ok := err.Data.(map[string]any)
	if !ok {
		t.Fatalf("Data = %#v, want a map carrying legacyCode", err.Data)
	}
	if data["legacyCode"] != -32000 {
		t.Errorf("legacyCode = %v, want -32000", data["legacyCode"])
	}
	if err.Code != CodeHandleNotResolvable {
		t.Errorf("Code = %d, want %d; the primary code must not change", err.Code, CodeHandleNotResolvable)
	}
}

func TestWithLegacyCodePreservesExistingData(t *testing.T) {
	err := WithLegacyCode(New(CodeScopeDenied, "denied", map[string]any{"scope": "ops.write"}))
	data := err.Data.(map[string]any)
	if data["scope"] != "ops.write" {
		t.Errorf("existing data was dropped: %#v", data)
	}
	if data["legacyCode"] != -32007 {
		t.Errorf("legacyCode = %v, want -32007", data["legacyCode"])
	}
}

func TestWithLegacyCodeIgnoresCodesThatNeverMoved(t *testing.T) {
	err := WithLegacyCode(New(CodeInvalidParams, "bad", nil))
	if err.Data != nil {
		t.Errorf("Data = %#v, want nil; -32602 never moved", err.Data)
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

// TestWithLegacyCodePreservesStructuredData. CodeScopeDenied carries its
// required scope as a struct, and §8.4 calls that the actionable part of the
// error. Nesting it under "detail" to make room for legacyCode would move the
// one field a client reads — a transition aid breaking what it exists to
// protect, with the flag on by default.
func TestWithLegacyCodePreservesStructuredData(t *testing.T) {
	payload := struct {
		RequiredScope string `json:"requiredScope"`
	}{RequiredScope: "warehouse:read"}

	err := WithLegacyCode(New(CodeScopeDenied, "denied", payload))
	data, ok := err.Data.(map[string]any)
	if !ok {
		t.Fatalf("Data = %#v, want a map", err.Data)
	}
	if data["requiredScope"] != "warehouse:read" {
		t.Errorf("requiredScope = %v, want warehouse:read; it must stay at the top level",
			data["requiredScope"])
	}
	if _, nested := data["detail"]; nested {
		t.Error(`structured data was nested under "detail"; a client reading ` +
			`error.data.requiredScope would find nothing there`)
	}
	if data["legacyCode"] != float64(-32007) && data["legacyCode"] != -32007 {
		t.Errorf("legacyCode = %v, want -32007", data["legacyCode"])
	}
}

// TestWithLegacyCodeFallsBackToDetailForANonObject. A bare string has nowhere
// to merge into, so it keeps the "detail" wrapper.
func TestWithLegacyCodeFallsBackToDetailForANonObject(t *testing.T) {
	err := WithLegacyCode(New(CodeHandleNotResolvable, "nope", "a bare string"))
	data := err.Data.(map[string]any)
	if data["detail"] != "a bare string" {
		t.Errorf(`detail = %v, want the original string`, data["detail"])
	}
	if data["legacyCode"] != -32000 {
		t.Errorf("legacyCode = %v, want -32000", data["legacyCode"])
	}
}
