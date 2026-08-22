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
}

func NewStdio(mux *Mux, info envelope.Info, negCfg envelope.NegotiationConfig) *Stdio {
	return &Stdio{mux: mux, info: info, negCfg: negCfg}
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
		return envelope.NewErrorResponse(nil, envelope.ErrParse(err.Error()))
	}
	if req.JSONRPC != envelope.JSONRPCVersion {
		return envelope.NewErrorResponse(req.ID,
			envelope.ErrInvalidParams("jsonrpc", req.JSONRPC, "must be \"2.0\""))
	}

	meta, err := envelope.ExtractMeta(req.Params)
	if err != nil {
		return envelope.NewErrorResponse(req.ID,
			envelope.ErrInvalidParams("_meta", err.Error(), "must be an object"))
	}

	outcome, rpcErr := envelope.Negotiate(meta, req.Method, s.negCfg)
	if rpcErr != nil {
		return envelope.NewErrorResponse(req.ID, rpcErr)
	}

	handler, rpcErr := s.mux.Lookup(req.Method)
	if rpcErr != nil {
		return envelope.NewErrorResponse(req.ID, rpcErr)
	}

	rctx := WithRequestContext(ctx, RequestContext{
		ProtocolVersion: outcome.Version,
		Legacy:          outcome.Legacy,
		Traceparent:     meta.Traceparent,
		ClientInfo:      meta.ClientInfo,
	})

	result, rpcErr := handler(rctx, req.Params)
	if rpcErr != nil {
		return envelope.NewErrorResponse(req.ID, rpcErr)
	}

	resultType := envelope.ResultComplete
	if tc, ok := result.(*envelope.ToolsCallResult); ok && len(tc.InputRequests) > 0 {
		resultType = envelope.ResultInputRequired
	}
	envelope.FinalizeWithTrace(result, resultType, s.info, outcome.Version, meta.Traceparent)

	encoded, err := json.Marshal(result)
	if err != nil {
		return envelope.NewErrorResponse(req.ID, envelope.ErrInternal("result could not be serialized"))
	}
	return envelope.NewResultResponse(req.ID, encoded)
}
