package envelope

import (
	"testing"
)

// testConfig is the negotiation configuration used by the matrix. Legacy
// support is ON so that the "version absent" row exercises the fallback path;
// the OFF case is covered separately by TestNegotiationLegacyDisabled.
func testConfig() NegotiationConfig {
	return NegotiationConfig{
		Supported:     []string{RevisionCurrent},
		LegacyVersion: RevisionLegacy,
		AllowLegacy:   true,
	}
}

// TestNegotiationMatrix is the fifteen-cell matrix mandated by
// docs/HANDOFF.md §8.1: {absent, 2025-11-25, 2026-07-28, 2099-01-01, malformed}
// × {server/discover, tools/list, tools/call}.
//
// The row that matters most is server/discover: it MUST be answerable without a
// negotiated version, because its entire purpose is to let a client find out
// what versions exist before committing to one. Serving -32022 from it makes the
// server undiscoverable.
func TestNegotiationMatrix(t *testing.T) {
	const (
		absent    = ""
		malformed = "not-a-revision"
		future    = "2099-01-01"
	)

	type cell struct {
		version   string
		method    string
		wantCode  int // 0 means "no error"
		wantLegcy bool
	}

	cells := []cell{
		// server/discover — answerable at every version state, including
		// none at all and ones this server has never heard of.
		{absent, MethodDiscover, 0, false},
		{RevisionLegacy, MethodDiscover, 0, false},
		{RevisionCurrent, MethodDiscover, 0, false},
		{future, MethodDiscover, 0, false},
		{malformed, MethodDiscover, 0, false},

		// tools/list — ordinary negotiation.
		{absent, "tools/list", 0, true},
		{RevisionLegacy, "tools/list", 0, true},
		{RevisionCurrent, "tools/list", 0, false},
		{future, "tools/list", CodeUnsupportedProtocolVersion, false},
		{malformed, "tools/list", CodeUnsupportedProtocolVersion, false},

		// tools/call — identical treatment; negotiation is per-request and
		// does not vary by which ordinary method is being called.
		{absent, "tools/call", 0, true},
		{RevisionLegacy, "tools/call", 0, true},
		{RevisionCurrent, "tools/call", 0, false},
		{future, "tools/call", CodeUnsupportedProtocolVersion, false},
		{malformed, "tools/call", CodeUnsupportedProtocolVersion, false},
	}

	if len(cells) != 15 {
		t.Fatalf("the matrix is specified as fifteen cells, got %d", len(cells))
	}

	for _, c := range cells {
		name := c.method + "/" + versionLabel(c.version)
		t.Run(name, func(t *testing.T) {
			meta := RequestMeta{ProtocolVersion: c.version}
			out, rpcErr := Negotiate(meta, c.method, testConfig())

			if c.wantCode == 0 {
				if rpcErr != nil {
					t.Fatalf("want success, got error code %d (%s)", rpcErr.Code, rpcErr.Message)
				}
				if out.Version == "" {
					t.Fatal("a successful negotiation must resolve a version")
				}
				if out.Legacy != c.wantLegcy {
					t.Fatalf("Legacy = %v, want %v", out.Legacy, c.wantLegcy)
				}
				return
			}

			if rpcErr == nil {
				t.Fatalf("want error code %d, got success (version %q)", c.wantCode, out.Version)
			}
			if rpcErr.Code != c.wantCode {
				t.Fatalf("code = %d, want %d", rpcErr.Code, c.wantCode)
			}
		})
	}
}

func versionLabel(v string) string {
	if v == "" {
		return "absent"
	}
	return v
}

// TestNegotiationUnsupportedListsSupportedVersions: a client that guessed wrong
// needs to know what to guess next, so the error data carries the list.
func TestNegotiationUnsupportedListsSupportedVersions(t *testing.T) {
	_, rpcErr := Negotiate(RequestMeta{ProtocolVersion: "2099-01-01"}, "tools/list", testConfig())
	if rpcErr == nil {
		t.Fatal("want -32022, got success")
	}
	data, ok := rpcErr.Data.(UnsupportedVersionData)
	if !ok {
		t.Fatalf("error data = %T, want UnsupportedVersionData", rpcErr.Data)
	}
	if len(data.SupportedVersions) == 0 {
		t.Fatal("supportedVersions must be listed so the client can retry correctly")
	}
	found := false
	for _, v := range data.SupportedVersions {
		if v == RevisionCurrent {
			found = true
		}
	}
	if !found {
		t.Fatalf("supportedVersions %v omits the revision this server implements", data.SupportedVersions)
	}
}

// TestNegotiationLegacyDisabled covers the fourth row of the §8.1 table:
// version absent with legacy support off is -32022, not a silent default.
func TestNegotiationLegacyDisabled(t *testing.T) {
	cfg := testConfig()
	cfg.AllowLegacy = false

	_, rpcErr := Negotiate(RequestMeta{ProtocolVersion: ""}, "tools/list", cfg)
	if rpcErr == nil {
		t.Fatal("want -32022 when the version is absent and legacy support is off")
	}
	if rpcErr.Code != CodeUnsupportedProtocolVersion {
		t.Fatalf("code = %d, want %d", rpcErr.Code, CodeUnsupportedProtocolVersion)
	}

	// server/discover stays exempt even here. A server whose legacy support is
	// off must still be discoverable, or a client can never learn why it was
	// refused.
	if _, err := Negotiate(RequestMeta{ProtocolVersion: ""}, MethodDiscover, cfg); err != nil {
		t.Fatalf("server/discover must answer without a negotiated version, got %d", err.Code)
	}
}

// TestDiscoverAnswerableWithoutNegotiatedVersion is called out by name in the
// handoff (WP-1 required tests). It overlaps the matrix deliberately: this is
// the property most likely to regress, and it deserves a test whose failure
// message says exactly what broke.
func TestDiscoverAnswerableWithoutNegotiatedVersion(t *testing.T) {
	for _, version := range []string{"", "2099-01-01", "garbage", RevisionLegacy} {
		out, rpcErr := Negotiate(RequestMeta{ProtocolVersion: version}, MethodDiscover, testConfig())
		if rpcErr != nil {
			t.Fatalf("server/discover refused version %q with code %d — the server is now undiscoverable",
				version, rpcErr.Code)
		}
		if out.Version == "" {
			t.Fatalf("server/discover at version %q resolved no version", version)
		}
	}
}

// TestLegacyFallbackIsRecorded: §8.1 requires a `deprecated.feature_used` event
// when a request is served under the legacy fallback. If the outcome does not
// carry the flag, nothing downstream can record it.
func TestLegacyFallbackIsRecorded(t *testing.T) {
	out, rpcErr := Negotiate(RequestMeta{ProtocolVersion: ""}, "tools/list", testConfig())
	if rpcErr != nil {
		t.Fatalf("unexpected error %d", rpcErr.Code)
	}
	if !out.Legacy {
		t.Fatal("a request served under the legacy fallback must be flagged so the deprecation event can be recorded")
	}
	if out.Version != RevisionLegacy {
		t.Fatalf("Version = %q, want the legacy revision %q", out.Version, RevisionLegacy)
	}
	if out.DeprecationEvent == "" {
		t.Fatal("the outcome must name the deprecation event to record")
	}
}

// TestMethodNewInCurrentRevisionRefusedUnderLegacy: the legacy fallback serves
// "if the operation exists in that revision". A method introduced by the
// stateless revision does not, so it cannot be served under 2025-11-25.
func TestMethodNewInCurrentRevisionRefusedUnderLegacy(t *testing.T) {
	// tools/call and tools/list exist in both revisions; a stateless-only
	// method does not. server/discover is the canonical example, but it is
	// exempt from negotiation, so the check uses the explicit set instead.
	if ExistsInLegacyRevision(MethodDiscover) {
		t.Fatal("server/discover is new in 2026-07-28 and must not be considered a legacy method")
	}
	for _, m := range []string{"tools/list", "tools/call", "resources/list", "prompts/list"} {
		if !ExistsInLegacyRevision(m) {
			t.Fatalf("%s exists in 2025-11-25 and must be servable under the legacy fallback", m)
		}
	}
}

// TestRequireCapability covers the fifth row of the §8.1 table.
func TestRequireCapability(t *testing.T) {
	meta := RequestMeta{ClientCapabilities: []byte(`{"elicitation":{}}`)}

	if err := RequireCapability(meta, "elicitation"); err != nil {
		t.Fatalf("declared capability was rejected: %d %s", err.Code, err.Message)
	}

	err := RequireCapability(meta, "sampling")
	if err == nil {
		t.Fatal("want -32021 for a capability the client did not declare")
	}
	if err.Code != CodeMissingRequiredClientCapability {
		t.Fatalf("code = %d, want %d", err.Code, CodeMissingRequiredClientCapability)
	}
	if !contains(err.Message, "sampling") {
		t.Fatalf("the error must name the missing capability; got %q", err.Message)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// TestRemovedMethodsStillExistInTheLegacyRevision.
//
// The distinction is easy to get wrong and produces a misleading error when you
// do: `ping` was removed by 2026-07-28 but it existed in 2025-11-25, so an
// unversioned request naming it must negotiate successfully and then be told by
// the dispatcher which revision removed it — not be told that its protocol
// version is unsupported, which is a different and untrue thing.
func TestRemovedMethodsStillExistInTheLegacyRevision(t *testing.T) {
	for _, m := range []string{"ping", "initialize", "logging/setLevel", "resources/subscribe"} {
		if !ExistsInLegacyRevision(m) {
			t.Errorf("%s existed in 2025-11-25; negotiation must not refuse it, "+
				"dispatch must report it as removed", m)
		}
		out, rpcErr := Negotiate(RequestMeta{ProtocolVersion: ""}, m, testConfig())
		if rpcErr != nil {
			t.Errorf("unversioned %s: negotiation returned %d, want success so the "+
				"dispatcher can answer method-not-found", m, rpcErr.Code)
			continue
		}
		if !out.Legacy {
			t.Errorf("unversioned %s must be flagged as a legacy fallback", m)
		}
	}
}

// TestExplicitLegacyVersionProceedsForAnyMethod. An explicitly declared
// 2025-11-25 is a supported version when the fallback is on, so it proceeds to
// dispatch regardless of the method. The existence gate belongs to the
// unversioned row, where the revision is a guess rather than a declaration.
func TestExplicitLegacyVersionProceedsForAnyMethod(t *testing.T) {
	out, rpcErr := Negotiate(
		RequestMeta{ProtocolVersion: RevisionLegacy}, "some/method/we/never/had", testConfig())
	if rpcErr != nil {
		t.Fatalf("explicit %s returned %d; a declared supported version must reach dispatch",
			RevisionLegacy, rpcErr.Code)
	}
	if !out.Legacy {
		t.Fatal("an explicitly declared legacy version is still a deprecation and must be recorded")
	}
}
