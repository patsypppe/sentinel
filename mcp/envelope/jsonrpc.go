package envelope

import "encoding/json"

// JSON-RPC wire types and the single point at which a result becomes a
// well-formed MCP result.
//
// §9.1: attaching `resultType` and `serverInfo` happens in ONE place, not per
// handler. A handler that builds its own response envelope will eventually
// forget a field, and the harness will catch it in public. The mechanism here is
// structural rather than procedural: Result is satisfied only by embedding Base,
// so a handler cannot return something that skipped the envelope.

const JSONRPCVersion = "2.0"

// Request is an incoming JSON-RPC request.
//
// ID is json.RawMessage because JSON-RPC permits a string, a number or null,
// and decoding a number through `any` would turn it into a float64 and change
// how it round-trips (§14 gotcha 2).
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is an outgoing JSON-RPC response. Exactly one of Result and Error is
// ever set.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// NewErrorResponse builds an error response preserving the request id.
func NewErrorResponse(id json.RawMessage, err *RPCError) Response {
	return Response{JSONRPC: JSONRPCVersion, ID: id, Error: err}
}

// NewResultResponse builds a success response.
func NewResultResponse(id json.RawMessage, result json.RawMessage) Response {
	return Response{JSONRPC: JSONRPCVersion, ID: id, Result: result}
}

// Base is embedded by every result type. Its unexported setter is what makes
// Result unforgeable from outside this package: a struct that does not embed
// Base cannot satisfy the interface, so it cannot be returned as a result at
// all, so it cannot skip Finalize.
type Base struct {
	ResultType ResultType  `json:"resultType"`
	Meta       *ResultMeta `json:"_meta,omitempty"`
}

func (b *Base) setEnvelope(rt ResultType, info Info) {
	b.ResultType = rt
	i := info
	if b.Meta == nil {
		b.Meta = &ResultMeta{}
	}
	b.Meta.ServerInfo = &i
}

// Result is any value the dispatcher may return to a client.
type Result interface {
	setEnvelope(rt ResultType, info Info)
}

// Cacheable is implemented by every list and read result. The 2026-07-28
// revision requires ttlMs and cacheScope on all of them.
type Cacheable interface {
	SetCache(CachePolicy)
}

// CacheFields is embedded by cacheable results.
type CacheFields struct {
	TTLMs      int        `json:"ttlMs"`
	CacheScope CacheScope `json:"cacheScope"`
}

func (c *CacheFields) SetCache(p CachePolicy) {
	c.TTLMs = p.TTLMs
	c.CacheScope = p.Scope
}

// Finalize stamps resultType and serverInfo onto a result. This is the one
// middleware §9.1 asks for; call it from the dispatcher and nowhere else.
func Finalize(r Result, rt ResultType, info Info) {
	r.setEnvelope(NormalizeResultType(rt), info)
}

// FinalizeWithTrace additionally echoes the negotiated version and the client's
// traceparent, so a client can confirm which revision served it and stitch the
// span without a second round trip.
func FinalizeWithTrace(r Result, rt ResultType, info Info, protocolVersion, traceparent string) {
	Finalize(r, rt, info)
	if b, ok := r.(interface{ meta() *ResultMeta }); ok {
		m := b.meta()
		m.ProtocolVersion = protocolVersion
		m.Traceparent = traceparent
	}
}

func (b *Base) meta() *ResultMeta {
	if b.Meta == nil {
		b.Meta = &ResultMeta{}
	}
	return b.Meta
}

// --- result types -----------------------------------------------------------
//
// Every field is a struct field, never a map: Go map iteration order is
// randomized, and a map anywhere in a serialized result makes the byte-stable
// manifest stable in tests and unstable in production (§14 gotcha 1).

// Capabilities is what server/discover advertises. Advertising a capability
// that is not implemented makes the server fail its own harness — which would
// happen in front of an audience, since step 2 of the demo is scanning
// ourselves. listChanged is false because subscriptions/listen is out of scope
// for the MVP, and being truthful about that is the point.
type Capabilities struct {
	Tools     ToolsCapability     `json:"tools"`
	Resources ResourcesCapability `json:"resources"`
	Prompts   PromptsCapability   `json:"prompts"`
}

type ToolsCapability struct {
	ListChanged bool `json:"listChanged"`
}

type ResourcesCapability struct {
	ListChanged bool `json:"listChanged"`
	Subscribe   bool `json:"subscribe"`
}

type PromptsCapability struct {
	ListChanged bool `json:"listChanged"`
}

type DiscoverResult struct {
	Base
	ServerInfo        Info         `json:"serverInfo"`
	SupportedVersions []string     `json:"supportedVersions"`
	Capabilities      Capabilities `json:"capabilities"`
	Extensions        []string     `json:"extensions"`
	Instructions      string       `json:"instructions,omitempty"`
	CacheFields
}

// ToolDescriptor is one entry in the manifest. Field order here is the canonical
// emission order (§8.3 step 2) — reordering it changes the manifest hash and
// invalidates every downstream client's cache, so it is not a cosmetic choice.
type ToolDescriptor struct {
	Name          string          `json:"name"`
	Title         string          `json:"title,omitempty"`
	Description   string          `json:"description"`
	InputSchema   json.RawMessage `json:"inputSchema"`
	OutputSchema  json.RawMessage `json:"outputSchema,omitempty"`
	Scopes        []string        `json:"scopes"`
	Reversibility string          `json:"reversibility"`
	TokenCap      int             `json:"tokenCap"`
	CacheTTLMs    int             `json:"cacheTtlMs"`
	CacheScope    CacheScope      `json:"cacheScope"`
}

type ToolsListResult struct {
	Base
	Tools        []ToolDescriptor `json:"tools"`
	ManifestHash string           `json:"manifestHash"`
	CacheFields
}

// ContentBlock is a single piece of tool output.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
	URI  string `json:"uri,omitempty"`
}

// InputRequest is one thing the server needs from the user before it can
// finish. The server never calls the client to ask; it returns these and the
// client retries (§8.5).
type InputRequest struct {
	Name        string          `json:"name"`
	Kind        string          `json:"kind"`
	Prompt      string          `json:"prompt"`
	Schema      json.RawMessage `json:"schema,omitempty"`
	Destructive bool            `json:"destructive,omitempty"`
}

type ToolsCallResult struct {
	Base
	Content           []ContentBlock  `json:"content,omitempty"`
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	IsError           bool            `json:"isError,omitempty"`
	// InputRequests and RequestState are set only when ResultType is
	// input_required. RequestState is AEAD-sealed, not encoded: the client
	// stores and returns it opaquely and cannot forge one (§7.5).
	InputRequests []InputRequest `json:"inputRequests,omitempty"`
	RequestState  string         `json:"requestState,omitempty"`
}

type ResourceDescriptor struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

type ResourcesListResult struct {
	Base
	Resources []ResourceDescriptor `json:"resources"`
	CacheFields
}

type ResourceTemplateDescriptor struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

type ResourceTemplatesListResult struct {
	Base
	ResourceTemplates []ResourceTemplateDescriptor `json:"resourceTemplates"`
	CacheFields
}

type ResourceContents struct {
	URI      string `json:"uri"`
	MIMEType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
}

type ResourcesReadResult struct {
	Base
	Contents []ResourceContents `json:"contents"`
	CacheFields
}

type PromptDescriptor struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type PromptsListResult struct {
	Base
	Prompts []PromptDescriptor `json:"prompts"`
	CacheFields
}
