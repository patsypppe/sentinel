package authz

import (
	"strings"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
)

// Scope handling.
//
// Scopes are matched by EXACT string equality everywhere in this repository —
// in registry.Principal.HasScope, in the warehouse allowlist, and here. There
// is no wildcard, no prefix rule and no hierarchy, because each of those is a
// way for a scope to grant more than it appears to.

// ParseScopes splits an OAuth `scope` claim, which is space-delimited by
// RFC 6749. Commas are tolerated because tokens in the wild use them, and
// rejecting a token over a delimiter would be a compatibility failure dressed
// up as a security control.
func ParseScopes(claim string) []string {
	// An explicitly empty slice, never nil: "this principal holds no scopes" is
	// a determination, and nil reads as "not determined".
	scopes := []string{}
	for _, field := range strings.FieldsFunc(claim, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t'
	}) {
		if field != "" {
			scopes = append(scopes, field)
		}
	}
	return scopes
}

// RPCError renders an authentication failure for the wire.
//
// Every failure maps to ONE code and ONE message. The distinction between
// "wrong audience", "wrong issuer", "expired" and "bad signature" is useful in a
// server log and is an oracle on the wire: a caller probing with a token they
// hold should not learn which of those it failed on, because each answer narrows
// what to try next.
//
// The message names the two things a legitimate caller can act on — which
// audience and which issuer this server accepts — because those are published
// facts, not secrets, and withholding them only obstructs the honest client.
func RPCError(cfg Config) *envelope.RPCError {
	return envelope.New(envelope.CodeInvalidRequest,
		"the presented token was not accepted; this server accepts tokens issued by "+
			cfg.Issuer+" with audience "+cfg.Audience,
		nil)
}
