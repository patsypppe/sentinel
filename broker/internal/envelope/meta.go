// Package envelope owns the MCP 2026-07-28 request/result envelope: `_meta`
// parsing, version negotiation, the error-code allocation, and the single point
// at which `resultType` and `serverInfo` are attached to a result.
//
// Nothing here touches a network or a database. That is deliberate — negotiation
// runs on every single request now that the handshake is gone, so it has to be
// a cheap pure function.
package envelope

import "encoding/json"

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

// ExtractMeta pulls `_meta` out of a params object. Absent params and absent
// `_meta` are both fine — they mean "no version declared", which the negotiation
// table handles explicitly rather than treating as an error here.
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
