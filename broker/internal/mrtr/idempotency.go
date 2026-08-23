package mrtr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/patsypppe/sentinel/broker/internal/canonical"
)

// Argument hashing for retry verification.
//
// A retry must carry the SAME arguments as the original call. The user approved
// a specific action; honouring a retry that quietly changed the target would
// make the approval a lie, and it is the obvious way to turn a confirmation
// prompt into a rubber stamp.

// ArgumentsHash canonicalizes arguments and returns "sha256:" + hex.
//
// Canonicalization matters here for a reason specific to retries: a client that
// re-serializes its arguments between the original call and the retry may emit
// the same VALUE with different BYTES — different key order, different
// whitespace. Hashing the raw bytes would reject that honest client as a
// mutation. Hashing the canonical form compares what was actually approved.
func ArgumentsHash(args json.RawMessage) (string, error) {
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	canonicalBytes, err := canonical.Bytes(args)
	if err != nil {
		return "", fmt.Errorf("mrtr: canonicalize arguments: %w", err)
	}
	sum := sha256.Sum256(canonicalBytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ArgumentsMatch compares a retry's arguments against a recorded hash.
func ArgumentsMatch(recorded string, args json.RawMessage) (bool, error) {
	got, err := ArgumentsHash(args)
	if err != nil {
		return false, err
	}
	return got == recorded, nil
}
