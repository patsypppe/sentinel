// Package envelope owns the MCP 2026-07-28 request/result envelope: `_meta`
// parsing, version negotiation, the error-code allocation, and the single point
// at which `resultType` and `serverInfo` are attached to a result.
//
// Nothing here touches a network or a database. That is deliberate — negotiation
// runs on every single request now that the handshake is gone, so it has to be
// a cheap pure function.
package envelope

import (
	"bytes"
	"encoding/json"
)

// Protocol revisions this server knows about.
const (
	// RevisionCurrent is the stateless revision this server implements natively.
	RevisionCurrent = "2026-07-28"
	// RevisionLegacy is the last session-based revision, served only under the
	// explicitly-enabled legacy fallback and always recorded as a deprecation.
	RevisionLegacy = "2025-11-25"
)

// `_meta` keys. Namespaced exactly as the specification writes them; a typo here
// silently disables negotiation, so they are constants and never inline strings.
const (
	KeyProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	KeyClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	KeyClientInfo         = "io.modelcontextprotocol/clientInfo"
	KeyServerInfo         = "io.modelcontextprotocol/serverInfo"
	KeyLogLevel           = "io.modelcontextprotocol/logLevel"
	KeyTraceparent        = "traceparent"
	KeyTracestate         = "tracestate"
	KeyBaggage            = "baggage"
)

// Method names. server/discover is the one method that must answer without a
// negotiated version.
const (
	MethodDiscover              = "server/discover"
	MethodToolsList             = "tools/list"
	MethodToolsCall             = "tools/call"
	MethodResourcesList         = "resources/list"
	MethodResourceTemplatesList = "resources/templates/list"
	MethodResourcesRead         = "resources/read"
	MethodPromptsList           = "prompts/list"
)

// Info identifies a peer. Clients key cache entries on the (name, version) pair,
// so it is a protocol surface rather than a diagnostic.
type Info struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Title   string `json:"title,omitempty"`
}

// RequestMeta is the `_meta` object carried inside every request's params.
//
// ClientCapabilities stays json.RawMessage on purpose: it is pass-through data,
// and decoding it into `any` would turn its numbers into float64 (§14 gotcha 2).
type RequestMeta struct {
	ProtocolVersion    string          `json:"io.modelcontextprotocol/protocolVersion,omitempty"`
	ClientCapabilities json.RawMessage `json:"io.modelcontextprotocol/clientCapabilities,omitempty"`
	ClientInfo         *Info           `json:"io.modelcontextprotocol/clientInfo,omitempty"`
	LogLevel           string          `json:"io.modelcontextprotocol/logLevel,omitempty"`
	Traceparent        string          `json:"traceparent,omitempty"`
	Tracestate         string          `json:"tracestate,omitempty"`
	Baggage            string          `json:"baggage,omitempty"`
}

// ResultMeta is the `_meta` object echoed on every result.
type ResultMeta struct {
	ServerInfo      *Info  `json:"io.modelcontextprotocol/serverInfo,omitempty"`
	ProtocolVersion string `json:"io.modelcontextprotocol/protocolVersion,omitempty"`
	Traceparent     string `json:"traceparent,omitempty"`
}

// ResultType discriminates a finished result from one that needs another
// round trip. There is no third value: the server never calls the client.
type ResultType string

const (
	ResultComplete      ResultType = "complete"
	ResultInputRequired ResultType = "input_required"
)

// NormalizeResultType maps an absent resultType to "complete".
//
// An earlier-protocol server omits the field entirely, and the harness has to
// scan those servers without crashing (§7.1). This is the one place that
// tolerance lives; the broker itself never emits an empty resultType, which
// TestEveryResultCarriesResultType enforces.
func NormalizeResultType(rt ResultType) ResultType {
	if rt == "" {
		return ResultComplete
	}
	return rt
}

// CacheScope controls who may reuse a cached result.
type CacheScope string

const (
	// ScopePrivate: only the requesting principal may reuse it. Correct whenever
	// the response varies by scopes — a shared intermediary serving one tenant's
	// result to another is a cross-tenant disclosure.
	ScopePrivate CacheScope = "private"
	// ScopePublic: safe for a shared intermediary. Use only when the response
	// genuinely does not vary by principal.
	ScopePublic CacheScope = "public"
)

// CachePolicy is the CacheableResult payload required on every list and read
// result by the 2026-07-28 revision.
type CachePolicy struct {
	TTLMs int        `json:"ttlMs"`
	Scope CacheScope `json:"cacheScope"`
}

// DefaultToolsListCachePolicy is private because the visible tool set varies
// with the principal's scopes (§8.3). Changing this to public would let a shared
// intermediary serve one tenant's tool list to another.
var DefaultToolsListCachePolicy = CachePolicy{TTLMs: 300_000, Scope: ScopePrivate}

// DefaultDiscoverCachePolicy is public: server/discover reports identity,
// supported versions and capabilities, none of which vary by principal.
var DefaultDiscoverCachePolicy = CachePolicy{TTLMs: 600_000, Scope: ScopePublic}

// HasClientCapabilities reports whether the client declared its capabilities.
//
// A literal `null` counts as absent. "Required: Yes" is a requirement to say
// what the client can do, and null says nothing — a client with no capabilities
// declares `{}`, which is a statement, rather than null, which is the absence
// of one.
func (m RequestMeta) HasClientCapabilities() bool {
	trimmed := bytes.TrimSpace(m.ClientCapabilities)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

// RequireMetaFields enforces the base protocol's required-field table:
//
//	io.modelcontextprotocol/protocolVersion     Required: Yes
//	io.modelcontextprotocol/clientInfo          Required: No
//	io.modelcontextprotocol/clientCapabilities  Required: Yes
//
// "A request missing any required field is malformed; the server MUST reject it
// with JSON-RPC error code -32602 (Invalid params)."
//
// clientInfo is deliberately NOT checked. It is Required: No, and demanding it
// would be the mirror-image defect of serving a request that omits a field that
// is required: refusing traffic that satisfies every MUST.
//
// The two required fields are not symmetrical, because the specification's own
// backward-compatibility carve-out is not symmetrical:
//
//   - protocolVersion has one. A client that pre-dates the field declares no
//     version anywhere, and AllowLegacy — BROKER_ALLOW_LEGACY_UNVERSIONED — is
//     the switch deciding whether this server still serves such a client. So
//     absence is checked THROUGH that switch rather than around it: with the
//     fallback on, an unversioned request keeps working and is recorded as a
//     deprecation; with it off, absence is exactly the malformed request the
//     specification describes. server/discover is exempt either way — its whole
//     purpose is to let a client find out which versions exist BEFORE it can
//     name one, so refusing it for not naming one makes the server
//     undiscoverable.
//   - clientCapabilities has none. Nothing in the specification makes it
//     optional for an older client, and it is what tells the server what the
//     client can be asked to do. A server that guesses returns an input request
//     to a client that cannot answer one, and the call stalls forever.
func RequireMetaFields(meta RequestMeta, method string, cfg NegotiationConfig) *RPCError {
	if !meta.HasClientCapabilities() {
		return ErrMissingRequiredMetaField(KeyClientCapabilities,
			"it is what tells this server what the client can be asked to do; declare {} if the "+
				"client supports nothing beyond the base protocol")
	}
	if meta.ProtocolVersion == "" && !cfg.AllowLegacy && method != MethodDiscover {
		return ErrMissingRequiredMetaField(KeyProtocolVersion,
			"the handshake is gone, so every request declares its own version, and this server "+
				"does not serve clients that pre-date the field")
	}
	return nil
}

// ExtractMeta pulls `_meta` out of a params object. Absent params and absent
// `_meta` are both fine here — RequireMetaFields is what decides whether a
// missing field is fatal, and it needs the parse to have succeeded first.
func ExtractMeta(params json.RawMessage) (RequestMeta, error) {
	if len(params) == 0 {
		return RequestMeta{}, nil
	}
	var envelope struct {
		Meta *RequestMeta `json:"_meta"`
	}
	if err := json.Unmarshal(params, &envelope); err != nil {
		return RequestMeta{}, err
	}
	if envelope.Meta == nil {
		return RequestMeta{}, nil
	}
	return *envelope.Meta, nil
}
