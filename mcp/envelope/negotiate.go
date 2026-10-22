package envelope

import (
	"encoding/json"
	"fmt"
	"slices"
)

// Version negotiation, per docs/HANDOFF.md §8.1.
//
// There is no handshake any more, so this runs on EVERY request. It touches no
// I/O for that reason.

// NegotiationConfig is the server's negotiation posture.
type NegotiationConfig struct {
	// Supported lists the revisions this server implements natively.
	Supported []string
	// LegacyVersion is the revision an unversioned request is treated as when
	// AllowLegacy is set.
	LegacyVersion string
	// AllowLegacy enables the unversioned fallback. Off means an unversioned
	// request is refused outright rather than silently defaulted.
	AllowLegacy bool
}

// Outcome is a successful negotiation.
type Outcome struct {
	// Version is the revision this request will be served under.
	Version string
	// Legacy is true when the request was served through the unversioned
	// fallback, which obliges the caller to record DeprecationEvent.
	Legacy bool
	// DeprecationEvent names the event to record. Empty unless Legacy.
	DeprecationEvent string
}

// DeprecationEventUnversionedRequest is recorded whenever a request arrives
// with no protocol version and is served under the legacy fallback.
const DeprecationEventUnversionedRequest = "deprecated.feature_used/unversioned_request"

// UnsupportedVersionData rides on a -32022 so a client that guessed wrong knows
// what to guess next.
type UnsupportedVersionData struct {
	SupportedVersions []string `json:"supportedVersions"`
	Requested         string   `json:"requested,omitempty"`
}

// legacyMethods is the method surface of the 2025-11-25 revision — what
// EXISTED there, not what this server implements. §8.1's unversioned fallback
// says to "serve if the operation exists in that revision", and conflating the
// two questions produces a misleading answer: a client sending `ping` with no
// version would be told its protocol version is unsupported, when the real
// answer is that `ping` was removed. Existence gates negotiation; implementation
// gates dispatch, which is where method-not-found belongs.
//
// server/discover is deliberately absent: it is new in 2026-07-28, which is
// exactly why a method-not-found from it doubles as a backward-compatibility
// probe on stdio (§8.1).
var legacyMethods = map[string]bool{
	// Still present in 2026-07-28.
	MethodToolsList:             true,
	MethodToolsCall:             true,
	MethodResourcesList:         true,
	MethodResourceTemplatesList: true,
	MethodResourcesRead:         true,
	MethodPromptsList:           true,
	"prompts/get":               true,
	"completion/complete":       true,
	// Removed by 2026-07-28, but they existed in 2025-11-25, so an unversioned
	// request naming one negotiates successfully and is then told by the
	// dispatcher which revision removed it.
	"initialize":                       true,
	"ping":                             true,
	"logging/setLevel":                 true,
	"resources/subscribe":              true,
	"resources/unsubscribe":            true,
	"notifications/roots/list_changed": true,
	"sampling/createMessage":           true,
	"roots/list":                       true,
}

// ExistsInLegacyRevision reports whether a method exists in 2025-11-25.
func ExistsInLegacyRevision(method string) bool { return legacyMethods[method] }

// Negotiate resolves the revision a request will be served under.
//
// server/discover is the exception and it matters: it MUST be answerable
// without a negotiated version, because its whole purpose is to let a client
// find out what versions exist before committing to one. Serving -32022 from it
// makes the server undiscoverable — an easy bug and a fatal one.
func Negotiate(meta RequestMeta, method string, cfg NegotiationConfig) (Outcome, *RPCError) {
	native := RevisionCurrent
	if len(cfg.Supported) > 0 {
		native = cfg.Supported[0]
	}

	if method == MethodDiscover {
		// Answer at whatever version the client named if we speak it, and at
		// our own otherwise. Never refuse.
		if meta.ProtocolVersion != "" && slices.Contains(cfg.Supported, meta.ProtocolVersion) {
			return Outcome{Version: meta.ProtocolVersion}, nil
		}
		return Outcome{Version: native}, nil
	}

	if meta.ProtocolVersion == "" {
		if !cfg.AllowLegacy {
			return Outcome{}, unsupported(cfg, "")
		}
		if !ExistsInLegacyRevision(method) {
			// The fallback serves only operations that exist in the legacy
			// revision. A stateless-only method under an unversioned request is
			// a negotiation failure, not a method-not-found: the client needs to
			// be told to declare a version.
			return Outcome{}, unsupported(cfg, "")
		}
		return Outcome{
			Version:          cfg.LegacyVersion,
			Legacy:           true,
			DeprecationEvent: DeprecationEventUnversionedRequest,
		}, nil
	}

	if slices.Contains(cfg.Supported, meta.ProtocolVersion) {
		return Outcome{Version: meta.ProtocolVersion}, nil
	}

	// An explicitly-declared legacy version is a SUPPORTED version when the
	// fallback is enabled, so it proceeds for any method and lets the dispatcher
	// answer. There is no existence gate here: that gate belongs to the
	// unversioned row, where the revision is a guess rather than a declaration.
	if cfg.AllowLegacy && meta.ProtocolVersion == cfg.LegacyVersion {
		return Outcome{
			Version:          cfg.LegacyVersion,
			Legacy:           true,
			DeprecationEvent: DeprecationEventUnversionedRequest,
		}, nil
	}

	// Everything else — a future revision, a typo, a malformed string — is the
	// same failure. There is nothing to gain from distinguishing them, and the
	// supportedVersions list tells the client what to do next either way.
	return Outcome{}, unsupported(cfg, meta.ProtocolVersion)
}

func unsupported(cfg NegotiationConfig, requested string) *RPCError {
	supported := slices.Clone(cfg.Supported)
	if cfg.AllowLegacy && cfg.LegacyVersion != "" && !slices.Contains(supported, cfg.LegacyVersion) {
		supported = append(supported, cfg.LegacyVersion)
	}
	msg := "no protocol version declared in _meta." + KeyProtocolVersion
	if requested != "" {
		msg = fmt.Sprintf("unsupported protocol version %q", requested)
	}
	return New(CodeUnsupportedProtocolVersion, msg, UnsupportedVersionData{
		SupportedVersions: supported,
		Requested:         requested,
	})
}

// RequireCapability enforces the fifth row of the §8.1 table: an operation that
// needs a client capability the client did not declare is -32021, naming the
// capability so the client can declare it and retry.
func RequireCapability(meta RequestMeta, capability string) *RPCError {
	if len(meta.ClientCapabilities) > 0 {
		// Decoded into json.RawMessage values, never `any`: capability payloads
		// are pass-through and must not have their numbers coerced to float64.
		var declared map[string]json.RawMessage
		if err := json.Unmarshal(meta.ClientCapabilities, &declared); err == nil {
			if _, ok := declared[capability]; ok {
				return nil
			}
		}
	}
	return New(CodeMissingRequiredClientCapability,
		fmt.Sprintf("this operation requires the %q client capability, which was not declared in _meta.%s",
			capability, KeyClientCapabilities),
		struct {
			RequiredCapability string `json:"requiredCapability"`
		}{RequiredCapability: capability})
}
