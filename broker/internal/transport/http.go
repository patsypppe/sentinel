package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/patsypppe/sentinel/broker/internal/config"
	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/registry"
)

// maxBodyBytes caps a request body. A protocol server with one endpoint has no
// reason to accept an unbounded upload, and an explicit cap is cheaper than
// discovering the default is "all of memory".
const maxBodyBytes = 4 << 20 // 4 MiB

// Server is the Streamable HTTP transport: exactly one endpoint, POST /mcp.
type Server struct {
	mux    *Mux
	cfg    config.Config
	info   envelope.Info
	negCfg envelope.NegotiationConfig
	log    *slog.Logger
	// auth is the only source of a principal. Nil means every authenticated
	// method is refused, which is the correct failure mode for an
	// authentication layer that has not been configured.
	auth Authenticator
	// audit records every authenticated invocation. Nil disables recording,
	// which is correct only for tests and for `broker manifest`.
	audit AuditSink
	// onDeprecatedFeature is called when a request is served through the legacy
	// fallback. §8.1 requires the event to be recorded; wiring it as a callback
	// keeps the transport free of a dependency on the audit writer.
	onDeprecatedFeature func(ctx context.Context, event, method string)
	// legacyErrorCodes attaches data.legacyCode in writeError. Scheduled for
	// removal with the transition release.
	legacyErrorCodes bool
}

type Option func(*Server)

// WithAuthenticator wires the principal source. Without one, every method that
// needs a principal is refused — an authentication layer that has not been
// configured must fail closed, not open.
func WithAuthenticator(a Authenticator) Option {
	return func(s *Server) { s.auth = a }
}

// WithDeprecationRecorder wires the `deprecated.feature_used` sink.
func WithDeprecationRecorder(f func(ctx context.Context, event, method string)) Option {
	return func(s *Server) { s.onDeprecatedFeature = f }
}

// WithLegacyErrorCodes attaches data.legacyCode to errors whose code moved out
// of -32000…-32019 in this revision, so a client mid-migration can triage on
// either number.
//
// SCHEDULED FOR REMOVAL: it exists for the transition release only, and goes
// away with it. See BROKER_EMIT_LEGACY_ERROR_CODE.
func WithLegacyErrorCodes(on bool) Option {
	return func(s *Server) { s.legacyErrorCodes = on }
}

func NewServer(mux *Mux, cfg config.Config, info envelope.Info, log *slog.Logger, opts ...Option) *Server {
	s := &Server{
		mux:  mux,
		cfg:  cfg,
		info: info,
		negCfg: envelope.NegotiationConfig{
			Supported:     []string{envelope.RevisionCurrent},
			LegacyVersion: envelope.RevisionLegacy,
			AllowLegacy:   cfg.AllowLegacyUnversioned,
		},
		log: log,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Routes returns the mux. One endpoint; a framework would be unnecessary.
//
// Two patterns cover it. "POST /mcp" is the endpoint; the method-less "/mcp"
// catches everything else on that path, because the specification asks for 405
// on a GET or DELETE and ServeMux's own automatic 405 sends a text/plain body
// that is not a JSON-RPC error. ServeMux treats a pattern carrying a method as
// more specific than one that does not, so the two do not conflict and a POST
// still reaches handleMCP.
func (s *Server) Routes() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("POST /mcp", s.handleMCP)
	m.HandleFunc("/mcp", s.handleWrongMethod)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	return m
}

// handleWrongMethod answers a GET or DELETE — or anything else that is not a
// POST — on the MCP endpoint.
//
// "HTTP GET or DELETE to the MCP endpoint: respond with 405 Method Not
// Allowed." Those verbs opened and closed a SESSION in the previous revision,
// and there are no sessions here: answering them with anything other than a
// refusal would suggest this server has state a client can reach.
//
// The Origin check runs first, because it is a precondition on the connection
// rather than on the operation, and a browser page probing which verbs an
// internal endpoint answers has already learned something.
func (s *Server) handleWrongMethod(w http.ResponseWriter, r *http.Request) {
	if !s.checkOrigin(w, r) {
		return
	}
	w.Header().Set("Allow", http.MethodPost)
	s.writeErrorStatus(w, nil, envelope.ErrInvalidRequest(
		fmt.Sprintf("%s is not allowed on the MCP endpoint; this revision is stateless, so there "+
			"is no session for a GET to open or a DELETE to close — POST a JSON-RPC request instead",
			r.Method)),
		http.StatusMethodNotAllowed)
}

// checkOrigin enforces the Origin allowlist, and reports whether the request
// may proceed.
//
// "Servers MUST validate the Origin header on all incoming connections to
// prevent DNS rebinding attacks. If the Origin header is present and invalid,
// servers MUST respond with HTTP 403 Forbidden. The HTTP response body MAY
// comprise a JSON-RPC error response that has no id."
//
// A request with NO Origin is unaffected — that is every non-browser client,
// which is every client this server expects. A request WITH one came from a
// page, and with the allowlist empty (the default) there is no page that may
// drive this server, so it is refused. The id is deliberately absent from the
// body: the request may not have been parsed at all when this runs.
func (s *Server) checkOrigin(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if originAllowed(origin, s.cfg.AllowedOrigins) {
		return true
	}

	s.log.Warn("refusing a request from a disallowed Origin",
		"origin", origin, "path", r.URL.Path, "method", r.Method)
	s.writeErrorStatus(w, nil, envelope.ErrInvalidRequest(
		fmt.Sprintf("Origin %q is not allowed; set BROKER_ALLOWED_ORIGINS if a browser client "+
			"is meant to reach this server", origin)),
		http.StatusForbidden)
	return false
}

// originAllowed matches an Origin against the allowlist.
//
// Matching is exact after ASCII case folding, which is how RFC 6454 compares a
// scheme and a host. There is no wildcard and no suffix match on purpose: a
// pattern language in an allowlist is where "*.example.com" quietly starts
// matching "evil-example.com".
func originAllowed(origin string, allowed []string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(origin, candidate) {
			return true
		}
	}
	return false
}

// handleMCP is the pipeline of §9.1, in order:
//
//	validate the Origin → parse the envelope → validate headers → check the
//	required `_meta` fields → negotiate → authenticate → dispatch → attach
//	resultType and serverInfo → write the audit row → respond
//
// Two steps moved in WP-16 and the numbering below moved with them. Origin
// validation is new and goes first: it is a precondition on the CONNECTION, and
// the specification asks for it "on all incoming connections", so it must not
// wait on a body that may never parse. And parsing `_meta` now precedes the
// header contract, because MCP-Protocol-Version is validated against
// `_meta.protocolVersion` and cannot be checked without it. That reordering
// does not weaken §9.1's "headers first": parsing is not negotiating, and the
// header contract still precedes every protocol decision this server takes.
//
// Authentication (WP-7) and the audit row (WP-8) slot in at their marked points.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	// 1. Origin (§ Security Considerations of the transport). Before the body
	//    is even read: a page that can drive this server has already won by the
	//    time anything is parsed.
	if !s.checkOrigin(w, r) {
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		s.writeError(w, nil, envelope.ErrInvalidRequest("request body could not be read: "+err.Error()))
		return
	}

	var req envelope.Request
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, nil, envelope.ErrParse(err.Error()))
		return
	}
	if req.JSONRPC != envelope.JSONRPCVersion {
		s.writeError(w, req.ID, envelope.ErrInvalidParams(
			"jsonrpc", req.JSONRPC, "must be \"2.0\""))
		return
	}
	if req.Method == "" {
		s.writeError(w, req.ID, envelope.ErrInvalidRequest("method is required"))
		return
	}

	// A JSON-RPC NOTIFICATION — a request with no id — can never be answered
	// with a result: there is no id to correlate one against. The specification
	// allows two responses, "202 Accepted with no body" if the server accepts
	// it and "an HTTP error status code" if it cannot, and this revision
	// defines no client-to-server notification over Streamable HTTP at all. So
	// there is nothing this server could honestly accept, and it says so.
	//
	// Absent and null are distinguished deliberately: `"id": null` decodes to
	// the four bytes `null`, which is a request carrying a null id — malformed,
	// but not a notification — and falls through to the ordinary path.
	if len(req.ID) == 0 {
		s.writeErrorStatus(w, nil, envelope.ErrInvalidRequest(
			fmt.Sprintf("%q arrived as a JSON-RPC notification (no id), and this revision defines "+
				"no client-to-server notifications over Streamable HTTP; send a request with an id",
				req.Method)),
			http.StatusBadRequest)
		return
	}

	// 2. Envelope. Ahead of the header contract because the header contract
	//    cross-checks MCP-Protocol-Version against `_meta.protocolVersion`.
	meta, err := envelope.ExtractMeta(req.Params)
	if err != nil {
		s.writeError(w, req.ID, envelope.ErrInvalidParams("_meta", err.Error(), "must be an object"))
		return
	}

	// 3. Header contract (§8.2). Validated against the body so a gateway that
	//    routed on the headers and a server that acted on the body can never
	//    disagree about what happened.
	if rpcErr := ValidateHeaders(r.Header, req); rpcErr != nil {
		s.writeError(w, req.ID, rpcErr)
		return
	}
	if rpcErr := ValidateProtocolVersion(r.Header, meta); rpcErr != nil {
		s.writeError(w, req.ID, rpcErr)
		return
	}

	// 4. The required `_meta` fields. After the header contract, because a
	//    request that a gateway could not have routed is refused for THAT
	//    before its body is judged; before negotiation, because negotiating a
	//    version out of a malformed request would be answering a question the
	//    request was not entitled to ask.
	if rpcErr := envelope.RequireMetaFields(meta, req.Method, s.negCfg); rpcErr != nil {
		s.writeError(w, req.ID, rpcErr)
		return
	}

	// 5. Negotiation — on every request, because the handshake is gone.
	outcome, rpcErr := envelope.Negotiate(meta, req.Method, s.negCfg)
	if rpcErr != nil {
		s.writeError(w, req.ID, rpcErr)
		return
	}
	if outcome.Legacy && s.onDeprecatedFeature != nil {
		s.onDeprecatedFeature(r.Context(), outcome.DeprecationEvent, req.Method)
	}

	// 6. Dispatch lookup, before authentication, so an unknown method is
	//    reported as unknown rather than as an authentication failure. Knowing
	//    which methods exist is not a secret — server/discover publishes the
	//    whole surface — so there is nothing to protect by conflating them.
	handler, rpcErr := s.mux.Lookup(req.Method)
	if rpcErr != nil {
		s.writeError(w, req.ID, rpcErr)
		return
	}

	ctx := WithRequestContext(r.Context(), RequestContext{
		ProtocolVersion: outcome.Version,
		Legacy:          outcome.Legacy,
		Traceparent:     meta.Traceparent,
		ClientInfo:      meta.ClientInfo,
	})

	var principal registry.Principal

	// 7. Authentication and audience validation. WP-7 supplies the real
	//    Authenticator; whatever it is, it is the only place a token is
	//    accepted. Methods that need no principal — discovery and the list
	//    endpoints — skip it, because requiring a token to find out what a
	//    server supports would make it undiscoverable to a client that has not
	//    yet learned which token to get.
	if methodNeedsPrincipal(req.Method) {
		if s.auth == nil {
			s.writeError(w, req.ID, envelope.ErrInternal(
				"this server has no authenticator configured and cannot serve authenticated methods"))
			return
		}
		p, authErr := s.auth.Authenticate(r)
		if authErr != nil {
			s.writeError(w, req.ID, authErr)
			return
		}
		ctx = WithPrincipal(ctx, p)
		principal = p
	}

	// 8. Dispatch.
	result, rpcErr := handler(ctx, req.Params)

	// 9. The audit row, BEFORE the response is written (§8.7), and covering
	//    failures as well as successes — a refused call is exactly the kind an
	//    investigation asks about later.
	//
	//    A failure here fails the invocation, including one that had already
	//    succeeded: an action nobody can attest to did not happen, and reporting
	//    success for it would make the log's silence a lie.
	if auditable(req.Method) {
		if auditErr := s.recordInvocation(
			ctx, req.Method, req.Params, principal,
			outcome.Version, meta.Traceparent, rpcErr, started,
		); auditErr != nil {
			s.log.Error("audit write failed; failing the invocation",
				"method", req.Method, "err", auditErr)
			s.writeError(w, req.ID, envelope.New(envelope.CodeAuditWriteFailed,
				"this invocation could not be recorded, so it was not performed", nil))
			return
		}
	}

	if rpcErr != nil {
		s.writeError(w, req.ID, rpcErr)
		return
	}

	// 10. The one place resultType and serverInfo are attached. A handler that
	//    built its own envelope would eventually forget a field and the harness
	//    would catch it in public, so handlers are not given the chance.
	resultType := envelope.ResultComplete
	if tc, ok := result.(*envelope.ToolsCallResult); ok && len(tc.InputRequests) > 0 {
		resultType = envelope.ResultInputRequired
	}
	envelope.FinalizeWithTrace(result, resultType, s.info, outcome.Version, meta.Traceparent)

	encoded, err := json.Marshal(result)
	if err != nil {
		s.writeError(w, req.ID, envelope.ErrInternal("result could not be serialized"))
		return
	}

	s.write(w, envelope.NewResultResponse(req.ID, encoded), http.StatusOK)
}

// writeError is the ONE place an RPCError becomes a response body on this
// transport, which is why the legacy-code decoration belongs here rather than
// at the several dozen call sites that produce one. Scattering it would make
// envelope/errors.go stop being the sole authority for the error surface.
//
// The status comes from httpStatusFor, so the mapping is a property of the code
// rather than of the call site: the same error cannot be a 400 down one path
// and a 200 down another.
func (s *Server) writeError(w http.ResponseWriter, id json.RawMessage, rpcErr *envelope.RPCError) {
	s.writeErrorStatus(w, id, rpcErr, httpStatusFor(rpcErr.Code))
}

// writeErrorStatus is writeError for the three refusals whose status the
// specification fixes at the TRANSPORT layer rather than by error code: 403 for
// a disallowed Origin, 405 for a GET or DELETE, and 400 for a notification.
// None of them has a JSON-RPC code of its own, so none of them can be mapped.
func (s *Server) writeErrorStatus(
	w http.ResponseWriter, id json.RawMessage, rpcErr *envelope.RPCError, status int,
) {
	if s.legacyErrorCodes {
		rpcErr = envelope.WithLegacyCode(rpcErr)
	}
	s.write(w, envelope.NewErrorResponse(id, rpcErr), status)
}

// httpStatusFor maps a JSON-RPC error code to the HTTP status the specification
// requires for it.
//
//	-32601  404  "If the server does not implement the requested RPC method, it
//	             MUST respond with 404 Not Found and a JSON-RPC error with code
//	             -32601."
//	-32020  400  "servers MUST return HTTP status 400 Bad Request and MUST
//	             include a JSON-RPC error response."
//	-32021  400  "On HTTP, the response status MUST be 400 Bad Request."
//	-32022  400  "it MUST respond with 400 Bad Request and an
//	             UnsupportedProtocolVersionError."
//	-32602  400  "A request missing any required field is malformed… On HTTP,
//	             the response status MUST be 400 Bad Request."
//
// Everything else stays 200, and that is not an oversight. A JSON-RPC error the
// specification does NOT assign a status to is an application-level outcome of
// a successful HTTP exchange — a denied scope, an unresolvable handle, an
// expired flow — and promoting it to 4xx/5xx would make gateways and client
// libraries retry, circuit-break and alert on results that are working exactly
// as designed. The rule is: the specification names the status, or it is 200.
//
// Note that -32602 covers resource-not-found in this revision, which therefore
// answers 400 rather than 404. That follows from the specification moving the
// code, and mapping by code is what keeps the mapping auditable.
func httpStatusFor(code int) int {
	switch code {
	case envelope.CodeMethodNotFound:
		return http.StatusNotFound
	case envelope.CodeHeaderMismatch,
		envelope.CodeMissingRequiredClientCapability,
		envelope.CodeUnsupportedProtocolVersion,
		envelope.CodeInvalidParams:
		return http.StatusBadRequest
	default:
		return http.StatusOK
	}
}

// write emits the response.
//
// Content-Type is set on EVERY path through here, error paths included: "the
// server MUST return either Content-Type: application/json… or Content-Type:
// text/event-stream". This server streams nothing, so it is always the former.
func (s *Server) write(w http.ResponseWriter, resp envelope.Response, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.Error("response could not be written", "err", err)
	}
}

// methodNeedsPrincipal reports whether a method acts on a principal's behalf.
//
// Discovery and the list endpoints do not. Requiring a token to find out what a
// server supports would make it undiscoverable to a client that has not yet
// learned which token to get, which is the same failure as refusing
// server/discover for an unsupported version.
func methodNeedsPrincipal(method string) bool {
	switch method {
	case envelope.MethodDiscover,
		envelope.MethodToolsList,
		envelope.MethodResourcesList,
		envelope.MethodResourceTemplatesList,
		envelope.MethodPromptsList:
		return false
	default:
		return true
	}
}

// RequestContext carries per-request protocol facts down to handlers without a
// session — there is no session, and nothing here is keyed by connection.
type RequestContext struct {
	ProtocolVersion string
	Legacy          bool
	Traceparent     string
	ClientInfo      *envelope.Info
}

type requestContextKey struct{}

func WithRequestContext(ctx context.Context, rc RequestContext) context.Context {
	return context.WithValue(ctx, requestContextKey{}, rc)
}

// FromContext returns the per-request protocol facts.
func FromContext(ctx context.Context) (RequestContext, bool) {
	rc, ok := ctx.Value(requestContextKey{}).(RequestContext)
	return rc, ok
}
