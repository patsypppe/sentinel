package envelope

import (
	"encoding/json"
	"fmt"
)

// This file is the ONLY place error codes are defined (docs/HANDOFF.md §5,
// layout rules). A reviewer should be able to audit the server's entire error
// surface by reading it, and TestNoErrorInReservedRange enumerates it to prove
// nothing was allocated inside the specification's range.
//
// The 2026-07-28 allocation policy partitions the JSON-RPC server-error range:
//
//	-32000 … -32019   LEGACY. Allocated by implementations before the policy
//	                  existed. "New codes MUST NOT be allocated in this
//	                  sub-range, and new implementations SHOULD NOT use codes
//	                  from this sub-range at all."
//	-32020 … -32099   reserved for the specification — never allocate here
//
// And: "New error codes for purposes not defined by this specification SHOULD
// be allocated outside the JSON-RPC reserved range (-32768 to -32000)."
//
// Sentinel is a new implementation, so its own codes live at 1000…1019 —
// outside the reserved range entirely. They were at -32000…-32019 through
// v0.1.0, which this revision retired; LegacyCode maps each new code back to
// the one it replaced, and WithLegacyCode attaches it for the transition.
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

// Sentinel's own codes, outside the JSON-RPC reserved range.
//
// The low ordinal is preserved from the pre-migration code so triage knowledge
// transfers: -32007 became 1007. 1002 is skipped for the same reason -32002
// was — it was resource-not-found before this revision, and reusing the ordinal
// makes triage ambiguous for exactly the clients most likely to be mid-migration.
const (
	// CodeHandleNotResolvable is returned for a handle that does not exist,
	// belongs to another principal, has expired, or has been revoked. The four
	// cases are deliberately indistinguishable — see handles/resolve.go.
	CodeHandleNotResolvable = 1000
	// CodeMRTRFlowExpired: the flow sat awaiting input past mrtr.flow_ttl.
	CodeMRTRFlowExpired = 1001
	// CodeMRTRArgumentsMutated: a retry whose arguments differ from the original.
	CodeMRTRArgumentsMutated = 1003
	// CodeMRTRStateInvalid: requestState failed to unseal — tampered, forged,
	// or sealed for a different tool.
	CodeMRTRStateInvalid = 1004
	// CodeMRTRResultNoLongerAvailable: the flow was consumed and the recorded
	// result has aged out of mrtr.replay_window. Never a re-execution.
	CodeMRTRResultNoLongerAvailable = 1005
	// CodeTokenBudgetExceeded: the response would exceed the tool's TokenCap
	// and no handle could be minted.
	CodeTokenBudgetExceeded = 1006
	// CodeScopeDenied: the principal's scopes do not cover the request.
	CodeScopeDenied = 1007
	// CodeAuditWriteFailed: the audit row could not be written, so the
	// invocation did not happen. Fail closed.
	CodeAuditWriteFailed = 1008
)

// legacyCodes maps each migrated code to the code it carried through v0.1.0.
//
// maps error codes to their predecessors and contains no secret.
//
//nolint:gosec // G101 pattern-matches the identifier as a credential table
var legacyCodes = map[int]int{
	CodeHandleNotResolvable:         -32000,
	CodeMRTRFlowExpired:             -32001,
	CodeMRTRArgumentsMutated:        -32003,
	CodeMRTRStateInvalid:            -32004,
	CodeMRTRResultNoLongerAvailable: -32005,
	CodeTokenBudgetExceeded:         -32006,
	CodeScopeDenied:                 -32007,
	CodeAuditWriteFailed:            -32008,
}

// LegacyCode returns the code this one replaced, if it replaced one.
func LegacyCode(code int) (int, bool) {
	old, ok := legacyCodes[code]
	return old, ok
}

// WithLegacyCode attaches data.legacyCode so a client mid-migration can triage
// on either number. Scheduled for removal — see BROKER_EMIT_LEGACY_ERROR_CODE.
//
// It merges at the TOP level of data, never underneath it. Most of our errors
// carry structured data as a struct rather than a map — CodeScopeDenied carries
// {"requiredScope": …}, which §8.4 says is the actionable part of the error —
// and nesting that under "detail" to make room for legacyCode would move the
// field a client actually reads. A transition aid that breaks the field it
// exists to protect is worse than no transition aid, so a struct is round-
// tripped through JSON and merged key-by-key.
//
// Only a non-object payload (a bare string, a number, an array) has nowhere to
// merge into, and only that falls back to "detail".
func WithLegacyCode(err *RPCError) *RPCError {
	old, ok := LegacyCode(err.Code)
	if !ok {
		return err
	}

	data := map[string]any{}
	switch existing := err.Data.(type) {
	case nil:
	case map[string]any:
		for k, v := range existing {
			data[k] = v
		}
	default:
		// Round-trip so a struct's json tags decide the key names, exactly as
		// they would have on the wire without this wrapper.
		if encoded, encErr := json.Marshal(existing); encErr == nil {
			var fields map[string]any
			if json.Unmarshal(encoded, &fields) == nil {
				for k, v := range fields {
					data[k] = v
				}
			} else {
				data["detail"] = existing
			}
		} else {
			data["detail"] = existing
		}
	}

	if _, taken := data["legacyCode"]; taken {
		// The payload already has a legacyCode of its own. Ours would silently
		// overwrite it, so leave the error alone rather than corrupt it.
		return err
	}
	data["legacyCode"] = old
	return &RPCError{Code: err.Code, Message: err.Message, Data: data}
}

// IsJSONRPCReserved reports whether code is inside JSON-RPC's reserved range.
func IsJSONRPCReserved(code int) bool { return code <= -32000 && code >= -32768 }

// IsLegacySubRange reports whether code is in the sub-range this revision retired.
func IsLegacySubRange(code int) bool { return code <= -32000 && code >= -32019 }

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
