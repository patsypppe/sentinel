package version

import "testing"

func TestIdentityIsPopulated(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must not be empty: it is echoed in serverInfo on every result")
	}
	if Name == "" {
		t.Fatal("Name must not be empty: it is echoed in serverInfo on every result")
	}
}

func TestProtocolVersionIsTheStatelessRevision(t *testing.T) {
	// The whole point of this project is that it is built natively on the
	// stateless revision. If this constant drifts, the negotiation table and
	// every conformance rule citation drift with it.
	if ProtocolVersion != "2026-07-28" {
		t.Fatalf("ProtocolVersion = %q, want 2026-07-28", ProtocolVersion)
	}
}
