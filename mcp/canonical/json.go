// Package canonical produces a byte-stable serialization of JSON values.
//
// Two things in this repository depend on the same property from opposite
// directions: the tool manifest must hash identically across restarts so client
// caches survive (docs/HANDOFF.md §8.3), and the audit chain must hash
// identically across verification runs or every row after a re-serialization
// looks tampered (§8.7). Both need "same value, same bytes", so both use this.
//
// The rules:
//
//   - object keys are sorted byte-wise;
//   - no insignificant whitespace;
//   - number tokens are preserved EXACTLY as they arrived.
//
// That last rule is the subtle one. Decoding a JSON number into `any` yields a
// float64, and re-encoding it can change 1e3 into 1000, or lose precision on a
// large integer — either of which silently changes a hash (§14 gotcha 2).
// Working in json.RawMessage throughout means the digits are never interpreted.
package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrFloatNotPermitted is returned by Strict when a non-integer number is
// found. The audit chain forbids floats outright: durations are integer
// milliseconds, and a float in a hashed field is a portability hazard across
// languages that do not agree on how to print one.
var ErrFloatNotPermitted = errors.New("canonical: floats are not permitted in hashed fields; use integer milliseconds")

// Options tunes canonicalization.
type Options struct {
	// RejectFloats fails on any non-integer number.
	RejectFloats bool
	// SortArrayKeys names object keys whose array values are sorted before
	// emission. The manifest uses this for "required" and "enum", where the
	// order carries no meaning but does change the hash (§8.3 step 3).
	SortArrayKeys map[string]bool
}

// Bytes canonicalizes raw with default options.
func Bytes(raw json.RawMessage) ([]byte, error) {
	return With(raw, Options{})
}

// Strict canonicalizes raw and rejects floats. Use for anything hashed into the
// audit chain.
func Strict(raw json.RawMessage) ([]byte, error) {
	return With(raw, Options{RejectFloats: true})
}

// Marshal canonicalizes an arbitrary Go value by round-tripping it through JSON
// first. Convenient for structs; the round trip is safe because the struct's
// own field types already fixed the number representations.
func Marshal(v any, opts Options) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: marshal: %w", err)
	}
	return With(raw, opts)
}

// With canonicalizes raw under opts.
func With(raw json.RawMessage, opts Options) ([]byte, error) {
	var buf bytes.Buffer
	if err := write(&buf, raw, opts, ""); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func write(buf *bytes.Buffer, raw json.RawMessage, opts Options, key string) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		buf.WriteString("null")
		return nil
	}

	switch trimmed[0] {
	case '{':
		return writeObject(buf, trimmed, opts)
	case '[':
		return writeArray(buf, trimmed, opts, key)
	default:
		return writeScalar(buf, trimmed, opts)
	}
}

func writeObject(buf *bytes.Buffer, raw json.RawMessage, opts Options) error {
	// map[string]json.RawMessage, never map[string]any: the values stay as
	// undecoded bytes so no number is ever interpreted.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("canonical: object: %w", err)
	}

	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	// Byte-wise over the UTF-8 encoding, not locale collation. sort.Strings on
	// Go strings is exactly bytes.Compare semantics.
	sort.Strings(keys)

	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		encoded, err := json.Marshal(k)
		if err != nil {
			return fmt.Errorf("canonical: key %q: %w", k, err)
		}
		buf.Write(encoded)
		buf.WriteByte(':')
		if err := write(buf, fields[k], opts, k); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

func writeArray(buf *bytes.Buffer, raw json.RawMessage, opts Options, key string) error {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return fmt.Errorf("canonical: array: %w", err)
	}

	rendered := make([][]byte, 0, len(items))
	for _, item := range items {
		var sub bytes.Buffer
		if err := write(&sub, item, opts, ""); err != nil {
			return err
		}
		rendered = append(rendered, sub.Bytes())
	}

	// Array order is meaningful in general and is preserved. It is sorted only
	// for the named keys, where the order carries no meaning but does change the
	// hash — `required: [a, b]` and `required: [b, a]` are the same schema.
	if opts.SortArrayKeys[key] {
		sort.Slice(rendered, func(i, j int) bool {
			return bytes.Compare(rendered[i], rendered[j]) < 0
		})
	}

	buf.WriteByte('[')
	for i, item := range rendered {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(item)
	}
	buf.WriteByte(']')
	return nil
}

func writeScalar(buf *bytes.Buffer, raw json.RawMessage, opts Options) error {
	switch {
	case bytes.Equal(raw, []byte("null")), bytes.Equal(raw, []byte("true")), bytes.Equal(raw, []byte("false")):
		buf.Write(raw)
		return nil
	case raw[0] == '"':
		// Re-encode through the string type so escaping is normalized; the
		// value itself is unchanged.
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("canonical: string: %w", err)
		}
		encoded, err := json.Marshal(s)
		if err != nil {
			return fmt.Errorf("canonical: string: %w", err)
		}
		buf.Write(encoded)
		return nil
	default:
		if opts.RejectFloats && isFloat(raw) {
			return fmt.Errorf("%w (found %s)", ErrFloatNotPermitted, raw)
		}
		// Number tokens are copied verbatim. Interpreting them is the bug.
		buf.Write(raw)
		return nil
	}
}

// isFloat reports whether a JSON number token carries a fraction or exponent.
// An integer written as 1e3 is treated as a float: it is a representation this
// package would have to normalize to compare, which is precisely what it
// refuses to do.
func isFloat(raw json.RawMessage) bool {
	s := string(raw)
	return strings.ContainsAny(s, ".eE")
}
