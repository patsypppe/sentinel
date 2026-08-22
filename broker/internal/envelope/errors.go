package envelope

import "fmt"

// This file is the ONLY place error codes are defined (docs/HANDOFF.md §5,
// layout rules). A reviewer should be able to audit the server's entire error
// surface by reading it, and TestNoErrorInReservedRange enumerates it to prove
// nothing was allocated inside the specification's range.
//
// The 2026-07-28 allocation policy partitions the JSON-RPC server-error range:
//
//	-32000 … -32019   implementation-defined — ours
//	-32020 … -32099   reserved for the specification — never allocate here
//
// Standard JSON-RPC codes pre-date the partition and sit outside it.

// Standard JSON-RPC 2.0 codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	// CodeInvalidParams now also covers resource-not-found, which moved here
	// from -32002 in this revision.
	CodeInvalidParams = -32602
	CodeInternalError = -32603
)

// Codes the specification defines inside its reserved range. These three are
// the only permitted occupants of -32020…-32099.
const (
	// CodeHeaderMismatch: Mcp-Method or Mcp-Name disagrees with the JSON-RPC body.
	CodeHeaderMismatch = -32020
	// CodeMissingRequiredClientCapability: the operation needs a capability the
	// client did not declare.
	CodeMissingRequiredClientCapability = -32021
	// CodeUnsupportedProtocolVersion: negotiation failure.
	CodeUnsupportedProtocolVersion = -32022
)

// Sentinel's own codes, all inside -32000…-32019.
//
// -32002 is deliberately skipped. It is legal for us to allocate, but it was
// resource-not-found before this revision, and reusing it makes error triage
// ambiguous for exactly the clients most likely to be mid-migration.
const (
	// CodeHandleNotResolvable is returned for a handle that does not exist,
	// belongs to another principal, has expired, or has been revoked. The four
	// cases are deliberately indistinguishable — see handles/resolve.go.
	CodeHandleNotResolvable = -32000
	// CodeMRTRFlowExpired: the flow sat awaiting input past mrtr.flow_ttl.
	CodeMRTRFlowExpired = -32001
	// CodeMRTRArgumentsMutated: a retry whose arguments differ from the original.
	CodeMRTRArgumentsMutated = -32003
	// CodeMRTRStateInvalid: requestState failed to unseal — tampered, forged,
	// or sealed for a different tool.
	CodeMRTRStateInvalid = -32004
	// CodeMRTRResultNoLongerAvailable: the flow was consumed and the recorded
	// result has aged out of mrtr.replay_window. Never a re-execution.
	CodeMRTRResultNoLongerAvailable = -32005
	// CodeTokenBudgetExceeded: the response would exceed the tool's TokenCap
	// and no handle could be minted.
	CodeTokenBudgetExceeded = -32006
	// CodeScopeDenied: the principal's scopes do not cover the request.
	CodeScopeDenied = -32007
	// CodeAuditWriteFailed: the audit row could not be written, so the
	// invocation did not happen. Fail closed.
	CodeAuditWriteFailed = -32008
)

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("jsonrpc %d: %s", e.Code, e.Message) }

// New builds an error. It is the only constructor; every helper below funnels
// through it so no code path can invent an unregistered code.
func New(code int, message string, data any) *RPCError {
	return &RPCError{Code: code, Message: message, Data: data}
}

// IsSpecReserved reports whether code falls in the range the specification
// reserves for itself.
func IsSpecReserved(code int) bool { return code <= -32020 && code >= -32099 }

// ImplementationCodes lists every code Sentinel allocates for itself.
func ImplementationCodes() []int {
	return []int{
		CodeHandleNotResolvable,
		CodeMRTRFlowExpired,
		CodeMRTRArgumentsMutated,
		CodeMRTRStateInvalid,
		CodeMRTRResultNoLongerAvailable,
		CodeTokenBudgetExceeded,
		CodeScopeDenied,
		CodeAuditWriteFailed,
	}
}

// AllCodes lists every code this server can emit, standard and allocated alike.
// The reserved-range test walks it, so a new code that is not registered here
// is a test failure rather than a silent escape.
func AllCodes() []int {
	standard := []int{
		CodeParseError,
		CodeInvalidRequest,
		CodeMethodNotFound,
		CodeInvalidParams,
		CodeInternalError,
		CodeHeaderMismatch,
		CodeMissingRequiredClientCapability,
		CodeUnsupportedProtocolVersion,
	}
	return append(standard, ImplementationCodes()...)
}

// codeNames maps each allocated code to its human name, for logs and for the
// conformance report, which prints the name beside the spec citation.
//
// maps error codes to their names and contains no secret.
//
//nolint:gosec // G101 pattern-matches the identifier as a credential table; it
var codeNames = map[int]string{
	CodeParseError:                      "ParseError",
	CodeInvalidRequest:                  "InvalidRequest",
	CodeMethodNotFound:                  "MethodNotFound",
	CodeInvalidParams:                   "InvalidParams",
	CodeInternalError:                   "InternalError",
	CodeHeaderMismatch:                  "HeaderMismatch",
	CodeMissingRequiredClientCapability: "MissingRequiredClientCapability",
	CodeUnsupportedProtocolVersion:      "UnsupportedProtocolVersion",
	CodeHandleNotResolvable:             "HandleNotResolvable",
	CodeMRTRFlowExpired:                 "MRTRFlowExpired",
	CodeMRTRArgumentsMutated:            "MRTRArgumentsMutated",
	CodeMRTRStateInvalid:                "MRTRStateInvalid",
	CodeMRTRResultNoLongerAvailable:     "MRTRResultNoLongerAvailable",
	CodeTokenBudgetExceeded:             "TokenBudgetExceeded",
	CodeScopeDenied:                     "ScopeDenied",
	CodeAuditWriteFailed:                "AuditWriteFailed",
}

// CodeName returns the human name for a code, for logs and conformance reports.
func CodeName(code int) string { return codeNames[code] }

// --- constructors -----------------------------------------------------------
//
// Errors are actionable by contract (§8.4): they name the offending field, show
// what was received, and show what would have worked. The model reads these and
// retries on them, so they are part of the tool's interface.

// ErrResourceNotFound. Note the code: this moved from -32002 to -32602 in the
// 2026-07-28 revision, and a server still emitting -32002 is non-conformant.
func ErrResourceNotFound(uri string) *RPCError {
	return New(CodeInvalidParams, fmt.Sprintf("resource not found: %q", uri), nil)
}

func ErrMethodNotFound(method string) *RPCError {
	return New(CodeMethodNotFound, fmt.Sprintf("unknown method %q", method), nil)
}

// RemovedMethodData explains why a method that used to work no longer does,
// which is more useful to a migrating client than a bare method-not-found.
type RemovedMethodData struct {
	RemovedIn   string `json:"removedIn"`
	Replacement string `json:"replacement,omitempty"`
}

// ErrMethodRemoved is method-not-found with provenance. §9.1 requires removed
// methods to answer rather than be silently absent from the router.
func ErrMethodRemoved(method, removedIn, replacement string) *RPCError {
	msg := fmt.Sprintf("method %q was removed in %s", method, removedIn)
	if replacement != "" {
		msg += fmt.Sprintf("; use %s instead", replacement)
	}
	return New(CodeMethodNotFound, msg, RemovedMethodData{RemovedIn: removedIn, Replacement: replacement})
}

func ErrParse(detail string) *RPCError {
	return New(CodeParseError, "malformed JSON: "+detail, nil)
}

func ErrInvalidRequest(detail string) *RPCError {
	return New(CodeInvalidRequest, detail, nil)
}

func ErrInternal(detail string) *RPCError {
	return New(CodeInternalError, detail, nil)
}

// ErrInvalidParams is the actionable-error workhorse: field, what arrived, and
// a value that would have worked.
func ErrInvalidParams(field, got, want string) *RPCError {
	return New(CodeInvalidParams,
		fmt.Sprintf("%q %s; got %q", field, want, got), nil)
}
