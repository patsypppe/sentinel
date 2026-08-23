package authz

import (
	"net/http"
	"strings"
	"time"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/registry"
)

// TokenAuthenticator adapts Validate to the transport's Authenticator
// interface. It is the production path; transport.DevAuthenticator is the
// local-development one and refuses every request unless explicitly enabled.
type TokenAuthenticator struct {
	cfg Config
	now func() time.Time
}

func NewTokenAuthenticator(cfg Config) *TokenAuthenticator {
	return &TokenAuthenticator{cfg: cfg, now: time.Now}
}

// Authenticate extracts and validates the bearer token.
//
// Every failure — a missing header, a malformed scheme, a bad signature, the
// wrong audience — produces the SAME wire error. Which check a token failed is
// useful in a server log and is an oracle on the wire: each distinct answer
// narrows what an attacker should try next.
func (a *TokenAuthenticator) Authenticate(r *http.Request) (registry.Principal, *envelope.RPCError) {
	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		return registry.Principal{}, RPCError(a.cfg)
	}

	p, err := Validate(token, a.cfg, a.now())
	if err != nil {
		return registry.Principal{}, RPCError(a.cfg)
	}
	return p, nil
}

// bearerToken parses an Authorization header.
//
// The scheme comparison is case-insensitive because RFC 7235 says the scheme is
// case-insensitive; the token is taken verbatim, because it is not.
func bearerToken(header string) (string, bool) {
	scheme, rest, found := strings.Cut(header, " ")
	if !found {
		return "", false
	}
	if !strings.EqualFold(scheme, "bearer") {
		return "", false
	}
	token := strings.TrimSpace(rest)
	if token == "" {
		return "", false
	}
	return token, true
}
