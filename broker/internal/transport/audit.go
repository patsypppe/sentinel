package transport

import (
	"context"
	"encoding/json"
	"time"

	"github.com/patsypppe/sentinel/broker/internal/audit"
	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/registry"
)

// AuditSink records an invocation. The transport depends on this rather than on
// the audit package's Writer so that the ordering rule of §8.7 stays visible
// here: the row is written BEFORE the response, and a failure fails the call.
type AuditSink interface {
	// Record persists an invocation. A non-nil error must fail the invocation:
	// an unauditable action does not happen.
	Record(ctx context.Context, r audit.Record) error
}

// WithAuditSink wires the audit log.
func WithAuditSink(s AuditSink) Option {
	return func(srv *Server) { srv.audit = s }
}

// auditableMethods are the ones that act on a principal's behalf and therefore
// need a row. Discovery and the list endpoints do not: they take no principal,
// have no effect, and recording every one of them would bury the invocations
// that matter under manifest fetches.
func auditable(method string) bool { return methodNeedsPrincipal(method) }

// recordInvocation builds and writes the audit row.
func (s *Server) recordInvocation(
	ctx context.Context,
	method string,
	params json.RawMessage,
	p registry.Principal,
	protocolVersion, traceparent string,
	rpcErr *envelope.RPCError,
	started time.Time,
) error {
	if s.audit == nil {
		return nil
	}

	toolName, arguments := method, json.RawMessage(nil)
	if method == envelope.MethodToolsCall {
		var call toolsCallParams
		if err := json.Unmarshal(params, &call); err == nil {
			if call.Name != "" {
				toolName = call.Name
			}
			arguments = call.Arguments
		}
	}

	// Redact returns no error by design: refusing to serve a request because
	// its arguments could not be prettied up for the log would be a denial of
	// service caused by the logging.
	redacted := audit.Redact(arguments)

	outcome, code := audit.OutcomeOK, 0
	if rpcErr != nil {
		outcome, code = audit.OutcomeError, rpcErr.Code
		if rpcErr.Code == envelope.CodeScopeDenied {
			outcome = audit.OutcomeDenied
		}
	}

	return s.audit.Record(ctx, audit.Record{
		OccurredAt:        started,
		TenantID:          p.TenantID,
		PrincipalID:       p.ID,
		ToolName:          toolName,
		ScopesExercised:   p.Scopes,
		ArgumentsRedacted: redacted,
		ProtocolVersion:   protocolVersion,
		TraceID:           traceparent,
		Outcome:           outcome,
		ErrorCode:         code,
		// Integer milliseconds, per §8.7: no floats in the hashed fields.
		DurationMs: time.Since(started).Milliseconds(),
	})
}
