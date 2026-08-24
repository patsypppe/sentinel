package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
)

// Stdio is a newline-delimited JSON-RPC adapter over the same dispatch path the
// HTTP transport uses. Sharing the path is a forcing function: any state that
// was secretly transport-specific shows up immediately as a stdio failure.
//
// On stdio, server/discover doubles as a backward-compatibility probe (§8.1).
// A 2025-11-25 server does not recognize the method, and the method-not-found
// error is itself the signal — which is exactly why server/discover is absent
// from the legacy method set.
type Stdio struct {
	mux    *Mux
	info   envelope.Info
	negCfg envelope.NegotiationConfig
	// legacyErrorCodes attaches data.legacyCode in errorResponse. Scheduled for
	// removal with the transition release.
	legacyErrorCodes bool
}

// StdioOption configures the stdio adapter. It is a separate type from Option
// only because Option configures *Server; the two carry the same intent.
type StdioOption func(*Stdio)

// WithStdioLegacyErrorCodes is WithLegacyErrorCodes for the stdio adapter: the
// two transports must not disagree about what an error looks like.
//
// SCHEDULED FOR REMOVAL: it exists for the transition release only. See
// BROKER_EMIT_LEGACY_ERROR_CODE.
func WithStdioLegacyErrorCodes(on bool) StdioOption {
	return func(s *Stdio) { s.legacyErrorCodes = on }
}

func NewStdio(mux *Mux, info envelope.Info, negCfg envelope.NegotiationConfig, opts ...StdioOption) *Stdio {
	s := &Stdio{mux: mux, info: info, negCfg: negCfg}
	for _, o := range opts {
		o(s)
	}
	return s
}

// errorResponse is stdio's counterpart to the HTTP transport's writeError: the
// ONE place an RPCError becomes a response body here, and therefore the only
// place the legacy-code decoration is applied.
func (s *Stdio) errorResponse(id json.RawMessage, rpcErr *envelope.RPCError) envelope.Response {
	if s.legacyErrorCodes {
		rpcErr = envelope.WithLegacyCode(rpcErr)
	}
	return envelope.NewErrorResponse(id, rpcErr)
}

// Serve reads requests until in is exhausted. The header contract does not
// apply here: Mcp-Method and Mcp-Name exist so an HTTP gateway can route
// without parsing the body, and there is no gateway on a pipe.
func (s *Stdio) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), maxBodyBytes)
	enc := json.NewEncoder(out)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		resp := s.handleLine(ctx, line)
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("write response: %w", err)
		}
	}
	return scanner.Err()
}

func (s *Stdio) handleLine(ctx context.Context, line []byte) envelope.Response {
	var req envelope.Request
	if err := json.Unmarshal(line, &req); err != nil {
		return s.errorResponse(nil, envelope.ErrParse(err.Error()))
	}
	if req.JSONRPC != envelope.JSONRPCVersion {
		return s.errorResponse(req.ID,
			envelope.ErrInvalidParams("jsonrpc", req.JSONRPC, "must be \"2.0\""))
	}

	meta, err := envelope.ExtractMeta(req.Params)
	if err != nil {
		return s.errorResponse(req.ID,
			envelope.ErrInvalidParams("_meta", err.Error(), "must be an object"))
	}

	outcome, rpcErr := envelope.Negotiate(meta, req.Method, s.negCfg)
	if rpcErr != nil {
		return s.errorResponse(req.ID, rpcErr)
	}

	handler, rpcErr := s.mux.Lookup(req.Method)
	if rpcErr != nil {
		return s.errorResponse(req.ID, rpcErr)
	}

	rctx := WithRequestContext(ctx, RequestContext{
		ProtocolVersion: outcome.Version,
		Legacy:          outcome.Legacy,
		Traceparent:     meta.Traceparent,
		ClientInfo:      meta.ClientInfo,
	})

	result, rpcErr := handler(rctx, req.Params)
	if rpcErr != nil {
		return s.errorResponse(req.ID, rpcErr)
	}

	resultType := envelope.ResultComplete
	if tc, ok := result.(*envelope.ToolsCallResult); ok && len(tc.InputRequests) > 0 {
		resultType = envelope.ResultInputRequired
	}
	envelope.FinalizeWithTrace(result, resultType, s.info, outcome.Version, meta.Traceparent)

	encoded, err := json.Marshal(result)
	if err != nil {
		return s.errorResponse(req.ID, envelope.ErrInternal("result could not be serialized"))
	}
	return envelope.NewResultResponse(req.ID, encoded)
}
