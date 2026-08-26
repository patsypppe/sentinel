package envelope

import (
	"encoding/json"
	"testing"
)

// The required-field table of the base protocol's `_meta` contract:
//
//	io.modelcontextprotocol/protocolVersion     Required: Yes
//	io.modelcontextprotocol/clientInfo          Required: No
//	io.modelcontextprotocol/clientCapabilities  Required: Yes
//
// "A request missing any required field is malformed; the server MUST reject it
// with JSON-RPC error code -32602 (Invalid params)."

func fallbackOn() NegotiationConfig {
	return NegotiationConfig{
		Supported:     []string{RevisionCurrent},
		LegacyVersion: RevisionLegacy,
		AllowLegacy:   true,
	}
}

func fallbackOff() NegotiationConfig {
	cfg := fallbackOn()
	cfg.AllowLegacy = false
	return cfg
}

func declared(caps string) RequestMeta {
	return RequestMeta{ClientCapabilities: json.RawMessage(caps)}
}

func TestClientCapabilitiesAreRequired(t *testing.T) {
	cases := []struct {
		desc string
		meta RequestMeta
	}{
		{desc: "absent", meta: RequestMeta{ProtocolVersion: RevisionCurrent}},
		{
			// null declares nothing. A client with no capabilities says {}.
			desc: "null",
			meta: RequestMeta{ProtocolVersion: RevisionCurrent, ClientCapabilities: json.RawMessage(`null`)},
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			err := RequireMetaFields(c.meta, MethodToolsList, fallbackOn())
			if err == nil {
				t.Fatal("a request without clientCapabilities must be rejected: the server would be " +
					"guessing what the client can be asked to do")
			}
			if err.Code != CodeInvalidParams {
				t.Fatalf("code = %d, want %d", err.Code, CodeInvalidParams)
			}
		})
	}
}

// TestClientCapabilitiesHaveNoLegacyEscapeHatch. The version field has one —
// BROKER_ALLOW_LEGACY_UNVERSIONED — because the specification carves out
// clients that pre-date it. Nothing carves out clientCapabilities.
func TestClientCapabilitiesHaveNoLegacyEscapeHatch(t *testing.T) {
	for _, cfg := range []NegotiationConfig{fallbackOn(), fallbackOff()} {
		if err := RequireMetaFields(RequestMeta{}, MethodToolsList, cfg); err == nil {
			t.Fatalf("clientCapabilities was optional with AllowLegacy=%v", cfg.AllowLegacy)
		}
	}
	// Including on discovery: the exemption there is from naming a VERSION, not
	// from saying what the client can do.
	if err := RequireMetaFields(RequestMeta{}, MethodDiscover, fallbackOn()); err == nil {
		t.Fatal("server/discover accepted a request that declared no clientCapabilities")
	}
}

// TestClientInfoIsOptional guards against a later "fix" that turns Required: No
// into a requirement. Demanding it would refuse traffic that satisfies every
// MUST, which is the mirror image of serving traffic that satisfies none.
func TestClientInfoIsOptional(t *testing.T) {
	meta := declared(`{}`)
	meta.ProtocolVersion = RevisionCurrent
	meta.ClientInfo = nil

	if err := RequireMetaFields(meta, MethodToolsList, fallbackOn()); err != nil {
		t.Fatalf("a request without clientInfo was refused (%d %s); the field is Required: No",
			err.Code, err.Message)
	}
}

// TestProtocolVersionIsRequiredThroughTheLegacySwitch. Absence of the field is
// exactly what BROKER_ALLOW_LEGACY_UNVERSIONED governs, so the check runs
// through that switch rather than around it.
func TestProtocolVersionIsRequiredThroughTheLegacySwitch(t *testing.T) {
	unversioned := declared(`{}`)

	if err := RequireMetaFields(unversioned, MethodToolsList, fallbackOn()); err != nil {
		t.Fatalf("the legacy fallback stopped serving an unversioned request: %d %s",
			err.Code, err.Message)
	}

	err := RequireMetaFields(unversioned, MethodToolsList, fallbackOff())
	if err == nil {
		t.Fatal("with the fallback off, a request declaring no version must be rejected")
	}
	if err.Code != CodeInvalidParams {
		t.Fatalf("code = %d, want %d: a missing required field is -32602, not a negotiation failure",
			err.Code, CodeInvalidParams)
	}
}

// TestDiscoverAnswersWithoutAVersionEvenWithTheFallbackOff. Its entire purpose
// is to let a client find out which versions exist BEFORE it can name one.
// Refusing it for not naming one makes the server undiscoverable.
func TestDiscoverAnswersWithoutAVersionEvenWithTheFallbackOff(t *testing.T) {
	if err := RequireMetaFields(declared(`{}`), MethodDiscover, fallbackOff()); err != nil {
		t.Fatalf("server/discover was refused for not declaring a version: %d %s",
			err.Code, err.Message)
	}
}
