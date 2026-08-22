package transport

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/patsypppe/sentinel/broker/internal/config"
	"github.com/patsypppe/sentinel/broker/internal/envelope"
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
	// onDeprecatedFeature is called when a request is served through the legacy
	// fallback. §8.1 requires the event to be recorded; wiring it as a callback
	// keeps the transport free of a dependency on the audit writer.
	onDeprecatedFeature func(ctx context.Context, event, method string)
}

type Option func(*Server)

// WithDeprecationRecorder wires the `deprecated.feature_used` sink.
func WithDeprecationRecorder(f func(ctx context.Context, event, method string)) Option {
	return func(s *Server) { s.onDeprecatedFeature = f }
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
func (s *Server) Routes() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("POST /mcp", s.handleMCP)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	return m
}

// handleMCP is the pipeline of §9.1, in order:
//
//	validate headers → parse the envelope → negotiate → authenticate →
//	dispatch → attach resultType and serverInfo → write the audit row → respond
//
// Authentication (WP-7) and the audit row (WP-8) slot in at their marked points.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
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

	// 1. Header contract (§8.2). Validated against the body so a gateway that
	//    routed on the headers and a server that acted on the body can never
	//    disagree about what happened.
	if rpcErr := ValidateHeaders(r.Header, req); rpcErr != nil {
		s.writeError(w, req.ID, rpcErr)
		return
	}

	// 2. Envelope.
	meta, err := envelope.ExtractMeta(req.Params)
	if err != nil {
		s.writeError(w, req.ID, envelope.ErrInvalidParams("_meta", err.Error(), "must be an object"))
		return
	}

	// 3. Negotiation — on every request, because the handshake is gone.
	outcome, rpcErr := envelope.Negotiate(meta, req.Method, s.negCfg)
	if rpcErr != nil {
		s.writeError(w, req.ID, rpcErr)
		return
	}
	if outcome.Legacy && s.onDeprecatedFeature != nil {
		s.onDeprecatedFeature(r.Context(), outcome.DeprecationEvent, req.Method)
	}

	// 4. Authentication and audience validation land here in WP-7.

	// 5. Dispatch.
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

	result, rpcErr := handler(ctx, req.Params)
	if rpcErr != nil {
		s.writeError(w, req.ID, rpcErr)
		return
	}

	// 6. The one place resultType and serverInfo are attached. A handler that
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

	// 7. The audit row lands here in WP-8, before the response is written.

	s.write(w, envelope.NewResultResponse(req.ID, encoded))
}

func (s *Server) writeError(w http.ResponseWriter, id json.RawMessage, rpcErr *envelope.RPCError) {
	s.write(w, envelope.NewErrorResponse(id, rpcErr))
}

// write emits the response. The HTTP status is always 200: a JSON-RPC error is
// a successful HTTP exchange carrying an application-level error, and returning
// 4xx would make gateways and clients retry things that are not retryable.
func (s *Server) write(w http.ResponseWriter, resp envelope.Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.Error("response could not be written", "err", err)
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
