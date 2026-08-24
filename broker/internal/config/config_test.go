package config

import (
	"testing"
	"time"
)

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("the documented defaults must validate: %v", err)
	}
}

// TestReplayWindowMustOutlastFlowTTL guards the recorded divergence in
// docs/PRD.md. A replay window shorter than the flow TTL re-opens the
// exactly-once hole it exists to close.
func TestReplayWindowMustOutlastFlowTTL(t *testing.T) {
	c := Default()
	c.MRTRFlowTTL = 48 * time.Hour
	c.MRTRReplayWindow = time.Minute

	if err := c.Validate(); err == nil {
		t.Fatal("a replay window shorter than the flow TTL must be rejected")
	}
}

func TestEmptyAudienceIsRejected(t *testing.T) {
	c := Default()
	c.OAuthAudience = ""
	if err := c.Validate(); err == nil {
		t.Fatal("an empty audience must be rejected: it is what every inbound token is checked against")
	}
}

func TestUnparseableDurationIsAnErrorNotADefault(t *testing.T) {
	t.Setenv("BROKER_MRTR_FLOW_TTL", "five minutes")
	if _, err := FromEnv(); err == nil {
		t.Fatal("a mistyped duration must fail loudly, not silently revert to the default")
	}
}

func TestEnvOverridesApply(t *testing.T) {
	t.Setenv("BROKER_MRTR_FLOW_TTL", "90s")
	t.Setenv("BROKER_DEFAULT_TOKEN_CAP", "1234")

	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if c.MRTRFlowTTL != 90*time.Second {
		t.Fatalf("MRTRFlowTTL = %s, want 90s", c.MRTRFlowTTL)
	}
	if c.DefaultTokenCap != 1234 {
		t.Fatalf("DefaultTokenCap = %d, want 1234", c.DefaultTokenCap)
	}
}

// TestLegacyErrorCodeEmissionDefaultsOn. The eight implementation codes moved
// out of -32000…-32019 in this revision, and data.legacyCode is what keeps a
// client that triaged on the old numbers working for one release. Defaulting it
// off would make the upgrade silently breaking for exactly those clients.
func TestLegacyErrorCodeEmissionDefaultsOn(t *testing.T) {
	if !Default().EmitLegacyErrorCode {
		t.Fatal("EmitLegacyErrorCode must default to true for the transition release")
	}
}

func TestLegacyErrorCodeEmissionCanBeDisabled(t *testing.T) {
	t.Setenv("BROKER_EMIT_LEGACY_ERROR_CODE", "false")

	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if c.EmitLegacyErrorCode {
		t.Fatal("BROKER_EMIT_LEGACY_ERROR_CODE=false must turn the transition aid off")
	}
}
