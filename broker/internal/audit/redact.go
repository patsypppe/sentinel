package audit

import (
	"encoding/json"
	"fmt"

	"github.com/patsypppe/sentinel/broker/internal/canonical"
)

// Argument redaction.
//
// The audit row records "redacted arguments" (§2 rule 4). Recording them raw
// would put whatever a caller passed — a query containing customer names, a
// token someone pasted into the wrong field — into a table designed to be kept
// forever and read by people investigating something else.

func canonicalStrict(args json.RawMessage) ([]byte, error) {
	out, err := canonical.Strict(args)
	if err != nil {
		// A float in the arguments is not the caller's fault and must not fail
		// the invocation, so fall back to the lenient form. The hash stays
		// consistent because CanonicalJSON does the same.
		return canonical.Bytes(args)
	}
	return out, nil
}

// sensitiveKeys are redacted wherever they appear, at any depth.
//
// The list is short and conservative on purpose. A long list invites the belief
// that everything else is safe to record, which it is not — the real control is
// that tools should not take secrets as arguments at all.
var sensitiveKeys = map[string]bool{
	"password":      true,
	"passwd":        true,
	"secret":        true,
	"token":         true,
	"access_token":  true,
	"refresh_token": true,
	"authorization": true,
	"api_key":       true,
	"apikey":        true,
	"private_key":   true,
	"credential":    true,
	"credentials":   true,
}

// Redacted is what replaces a redacted value.
const Redacted = `"[redacted]"`

// RedactionFailed is recorded in place of arguments that could not be
// processed. The row survives, and it says plainly that its arguments are
// missing rather than appearing to have had none.
const RedactionFailed = `{"redactionFailed":true}`

// Redact replaces sensitive values, preserving structure so the row still shows
// the SHAPE of the call — which fields were present, how many rows were asked
// for — while dropping the values that should not be kept.
//
// It returns no error, deliberately. Redaction must never fail an invocation:
// refusing to serve a request because its arguments could not be prettied up
// for the log would be a denial of service caused by the logging. An
// unredactable argument is recorded as RedactionFailed instead, which is
// honest about what is missing.
func Redact(args json.RawMessage) json.RawMessage {
	if len(args) == 0 {
		return json.RawMessage("{}")
	}
	out, err := redactValue(args)
	if err != nil {
		return json.RawMessage(RedactionFailed)
	}
	return out
}

func redactValue(raw json.RawMessage) (json.RawMessage, error) {
	trimmed := trimSpace(raw)
	if len(trimmed) == 0 {
		return json.RawMessage("null"), nil
	}

	switch trimmed[0] {
	case '{':
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &fields); err != nil {
			return nil, err
		}
		out := make(map[string]json.RawMessage, len(fields))
		for k, v := range fields {
			if sensitiveKeys[lower(k)] {
				out[k] = json.RawMessage(Redacted)
				continue
			}
			sub, err := redactValue(v)
			if err != nil {
				return nil, err
			}
			out[k] = sub
		}
		// Re-canonicalized so key order is fixed rather than left to map
		// iteration, which would make the same call hash differently each time.
		encoded, err := json.Marshal(out)
		if err != nil {
			return nil, err
		}
		return canonical.Bytes(encoded)

	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, err
		}
		out := make([]json.RawMessage, 0, len(items))
		for _, item := range items {
			sub, err := redactValue(item)
			if err != nil {
				return nil, err
			}
			out = append(out, sub)
		}
		encoded, err := json.Marshal(out)
		if err != nil {
			return nil, fmt.Errorf("audit: redact array: %w", err)
		}
		return encoded, nil

	default:
		return trimmed, nil
	}
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}
