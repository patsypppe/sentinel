// Package mrtr implements Multi Round-Trip Requests: the 2026-07-28
// replacement for server-initiated requests.
//
// Rule 2 of docs/HANDOFF.md §2. The server NEVER calls the client. When a tool
// needs a confirmation or additional input it returns
// resultType: "input_required" with an inputRequests array, and the CLIENT
// retries the original request — as a new JSON-RPC request with a NEW ID —
// carrying inputResponses.
//
// Because retries are client-driven they will be duplicated. A duplicate retry
// of a consumed flow must return the recorded result verbatim and perform ZERO
// additional side effects. That is the single hardest correctness property in
// the project, and idempotency.go plus engine.go exist to hold it.
package mrtr

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// requestState is SEALED, not encoded (§14 gotcha 6).
//
//	requestState = base64(nonce || AEAD(key, nonce, correlation_id||expiry, aad=tool_name))
//
// Base64 of JSON would be client-editable: a client could rewrite the
// correlation id, extend the expiry, or move a sealed state from one tool to
// another. Sealing makes a tampered or forged value indistinguishable from
// garbage, which is the entire point of choosing an AEAD over an encoding.
//
// The TOOL NAME is bound as additional authenticated data. A state sealed for
// ops.deployment_apply therefore cannot be replayed against any other tool: the
// AEAD tag simply fails to verify. Forgetting that binding is a listed pitfall,
// and TestSealedStateCannotBeReplayedAgainstAnotherTool exists for it.

// KeySize is the AEAD key length.
const KeySize = chacha20poly1305.KeySize

var (
	// ErrStateInvalid is returned for every unsealing failure: tampered,
	// truncated, forged, sealed with another key, or sealed for another tool.
	// One error, for the same reason handle resolution has one error.
	ErrStateInvalid = errors.New("requestState is not valid")
	// ErrStateExpired is returned when a well-formed state has aged out.
	ErrStateExpired = errors.New("requestState has expired")
)

// Sealer seals and unseals requestState.
type Sealer struct {
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
	}
	now func() time.Time
}

// NewSealer builds a sealer from a 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("mrtr: seal key must be %d bytes, got %d", KeySize, len(key))
	}
	// XChaCha20-Poly1305 rather than ChaCha20-Poly1305: its 192-bit nonce is
	// large enough that random nonces will not collide, so there is no counter
	// to keep and no state to carry across restarts. For a stateless server
	// that is not a convenience, it is a requirement.
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("mrtr: build aead: %w", err)
	}
	return &Sealer{aead: aead, now: time.Now}, nil
}

// WithClock replaces the clock, for tests.
func (s *Sealer) WithClock(now func() time.Time) *Sealer {
	return &Sealer{aead: s.aead, now: now}
}

// NewKey generates a fresh seal key.
func NewKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("mrtr: generate key: %w", err)
	}
	return key, nil
}

// plaintext layout: 8 bytes big-endian Unix expiry, then the correlation id.
// Fixed-width first so it can be read without a delimiter that the id might
// contain.
const expiryBytes = 8

// Seal produces the opaque requestState a client stores and returns.
func (s *Sealer) Seal(correlationID string, expiry time.Time, toolName string) (string, error) {
	if correlationID == "" {
		return "", errors.New("mrtr: correlation id must not be empty")
	}
	if toolName == "" {
		// An empty tool name would bind nothing, which silently removes the
		// cross-tool protection rather than weakening it.
		return "", errors.New("mrtr: tool name must not be empty: it is the AEAD's additional data")
	}

	plaintext := make([]byte, expiryBytes, expiryBytes+len(correlationID))
	binary.BigEndian.PutUint64(plaintext, uint64(expiry.Unix())) //nolint:gosec // Unix seconds are non-negative here
	plaintext = append(plaintext, correlationID...)

	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("mrtr: nonce: %w", err)
	}

	sealed := s.aead.Seal(nil, nonce, plaintext, []byte(toolName))
	return base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

// Unseal verifies and opens a requestState.
//
// toolName must be the tool the retry is calling. If it differs from the tool
// the state was sealed for, the AEAD tag fails and this returns ErrStateInvalid
// — the same error as outright garbage, because the two are indistinguishable
// to anyone who should not be able to tell them apart.
func (s *Sealer) Unseal(requestState, toolName string) (correlationID string, expiry time.Time, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(requestState)
	if err != nil {
		return "", time.Time{}, ErrStateInvalid
	}

	nonceSize := s.aead.NonceSize()
	if len(raw) < nonceSize+expiryBytes {
		return "", time.Time{}, ErrStateInvalid
	}

	plaintext, err := s.aead.Open(nil, raw[:nonceSize], raw[nonceSize:], []byte(toolName))
	if err != nil {
		return "", time.Time{}, ErrStateInvalid
	}
	if len(plaintext) <= expiryBytes {
		return "", time.Time{}, ErrStateInvalid
	}

	expiry = time.Unix(int64(binary.BigEndian.Uint64(plaintext[:expiryBytes])), 0) //nolint:gosec // round-trips the value written above
	correlationID = string(plaintext[expiryBytes:])

	// Expiry is checked AFTER the tag verifies. Checking it first would let an
	// attacker distinguish "expired" from "forged" by timing or by error, and
	// the sealed expiry is not trustworthy until the tag says it is.
	if s.now().After(expiry) {
		return "", time.Time{}, ErrStateExpired
	}
	return correlationID, expiry, nil
}
