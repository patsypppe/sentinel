package transport

import (
	"encoding/json"
	"time"

	"github.com/patsypppe/sentinel/mcp/envelope"
)

// Span is what the transport reports about one handled request, for a tracing
// exporter. It carries no argument values and no principal: a trace is shipped to a
// collector the audit log's access controls do not cover.
type Span struct {
	// Name is "mcp <method>", or "mcp tools/call <tool>" for a tool call.
	Name   string
	Method string
	Tool   string
	// Traceparent is the W3C trace context the client sent in _meta, or "".
	Traceparent string
	Start       time.Time
	End         time.Time
	// ErrorCode is the JSON-RPC error code, or 0 for success.
	ErrorCode    int
	ErrorMessage string
}

// WithSpanRecorder reports every dispatched request to f. f runs on the request path,
// so it must not block: an exporter should enqueue and return.
func WithSpanRecorder(f func(Span)) Option {
	return func(s *Server) { s.onSpan = f }
}

func (s *Server) recordSpan(
	method string, params json.RawMessage, traceparent string, rpcErr *envelope.RPCError, started time.Time,
) {
	if s.onSpan == nil {
		return
	}
	span := Span{
		Name: "mcp " + method, Method: method, Traceparent: traceparent,
		Start: started, End: time.Now(),
	}
	if method == envelope.MethodToolsCall {
		var call toolsCallParams
		if err := json.Unmarshal(params, &call); err == nil && call.Name != "" {
			span.Tool = call.Name
			span.Name += " " + call.Name
		}
	}
	if rpcErr != nil {
		span.ErrorCode, span.ErrorMessage = rpcErr.Code, rpcErr.Message
	}
	s.onSpan(span)
}
