// Package audit writes the append-only, hash-chained record of every tool
// invocation.
//
// docs/HANDOFF.md §2 rule 4: "The audit write FAILS THE INVOCATION if it fails.
// An unauditable action does not happen."
//
// Two mechanisms, doing different jobs. The GRANTS make the log append-only, so
// ordinary tampering is refused by Postgres. The HASH CHAIN makes tampering by
// anyone who can get past the grants — a superuser, someone with direct
// database access — detectable after the fact. Neither replaces the other.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/patsypppe/sentinel/broker/internal/canonical"
)

// GenesisHash is the prev_hash of the first row in a tenant's chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Outcome values.
const (
	OutcomeOK     = "ok"
	OutcomeError  = "error"
	OutcomeDenied = "denied"
)

// Record is one auditable invocation.
//
// Every field is hashed. The struct is the schema of what is attested to, so
// adding a field here changes every subsequent row's hash — which is correct,
// and why the field order is fixed by the canonical form rather than by
// declaration.
type Record struct {
	OccurredAt        time.Time       `json:"-"`
	TenantID          string          `json:"tenantId"`
	PrincipalID       string          `json:"principalId"`
	ToolName          string          `json:"toolName"`
	ScopesExercised   []string        `json:"scopesExercised"`
	ArgumentsRedacted json.RawMessage `json:"argumentsRedacted"`
	ProtocolVersion   string          `json:"protocolVersion"`
	TraceID           string          `json:"traceId"`
	CorrelationID     string          `json:"correlationId"`
	Outcome           string          `json:"outcome"`
	ErrorCode         int             `json:"errorCode"`
	// DurationMs is integer milliseconds. §8.7 forbids floats in the hashed
	// fields; a hash that depends on how a language prints a float is not
	// portable across the languages that might verify it.
	DurationMs int64 `json:"durationMs"`
	// OccurredAtUnixMs is what actually gets hashed, for the same reason: a
	// timestamp rendered as text depends on a format and a zone, an integer
	// does not.
	OccurredAtUnixMs int64 `json:"occurredAtUnixMs"`
}

// CanonicalJSON renders the auditable fields: keys sorted, no insignificant
// whitespace, and no floats.
func (r Record) CanonicalJSON() ([]byte, error) {
	// Scopes are a set; their order carries no meaning but would change the
	// hash, so it is fixed here rather than left to whatever produced them.
	scopes := append([]string(nil), r.ScopesExercised...)
	if scopes == nil {
		scopes = []string{}
	}
	sort.Strings(scopes)

	args := r.ArgumentsRedacted
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	canonicalArgs, err := canonical.Strict(args)
	if err != nil {
		return nil, fmt.Errorf("audit: redacted arguments: %w", err)
	}

	copyOf := r
	copyOf.ScopesExercised = scopes
	copyOf.ArgumentsRedacted = canonicalArgs
	copyOf.OccurredAtUnixMs = r.OccurredAt.UnixMilli()

	return canonical.Marshal(copyOf, canonical.Options{RejectFloats: true})
}

// RowHash computes sha256(prev_hash ‖ canonical_json(auditable_fields)).
//
// The previous hash is mixed in as its RAW BYTES rather than its hex text. That
// is not important cryptographically, but it is important that it is stated:
// two implementations that disagree about it produce chains that never verify
// against each other, and the disagreement is invisible until someone tries.
func RowHash(prevHash string, r Record) (string, error) {
	prev, err := hex.DecodeString(prevHash)
	if err != nil {
		return "", fmt.Errorf("audit: previous hash is not hex: %w", err)
	}
	if len(prev) != sha256.Size {
		return "", fmt.Errorf("audit: previous hash is %d bytes, want %d", len(prev), sha256.Size)
	}

	body, err := r.CanonicalJSON()
	if err != nil {
		return "", err
	}

	h := sha256.New()
	h.Write(prev)
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Break describes the first place a chain fails to verify.
type Break struct {
	Seq        int64
	OccurredAt time.Time
	TenantID   string
	// Expected is the hash recomputed from the row's own stored fields.
	Expected string
	// Stored is the hash on the row.
	Stored string
	// Reason distinguishes a rewritten row from a removed one.
	Reason string
}

func (b *Break) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "chain break at seq %d (%s, tenant %s): %s\n",
		b.Seq, b.OccurredAt.Format(time.RFC3339), b.TenantID, b.Reason)
	fmt.Fprintf(&sb, "  recomputed from the row's own fields: %s\n", b.Expected)
	fmt.Fprintf(&sb, "  stored on the row:                    %s", b.Stored)
	return sb.String()
}

// Break reasons.
const (
	ReasonRowRewritten = "the row's contents do not match its own hash — it was rewritten"
	ReasonLinkBroken   = "the row's prev_hash does not match the previous row — a row was removed, " +
		"reordered, or inserted"
)
