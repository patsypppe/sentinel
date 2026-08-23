// Package authz is where a token becomes a principal, and nowhere else.
//
// docs/HANDOFF.md §5 makes audience.go the only place a token is accepted, so a
// reviewer can audit the server's entire trust boundary by reading it. It is
// short for that reason.
//
// The specification is unambiguous (§2 rule 4): "MCP servers MUST NOT accept
// any token not explicitly issued for the MCP server." That is one exact
// comparison, and getting it slightly wrong — a prefix match, a substring
// check, a "contains" — turns it into no check at all.
package authz

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/patsypppe/sentinel/broker/internal/registry"
)

// Failure modes. They are distinct types internally so logs can tell them
// apart; the wire error deliberately does not — see RPCError.
var (
	ErrUnauthenticated = errors.New("authz: token signature could not be verified")
	ErrWrongAudience   = errors.New("authz: token was not issued for this server")
	ErrWrongIssuer     = errors.New("authz: token was issued by an unrecognised issuer")
	ErrExpired         = errors.New("authz: token has expired")
	ErrMalformed       = errors.New("authz: token is malformed")
)

// Config is the validation policy.
type Config struct {
	// Issuer must match the token's `iss` exactly.
	Issuer string
	// Audience must appear in the token's `aud` — by exact string equality,
	// never as a prefix or substring.
	Audience string
	// Keys verifies signatures.
	Keys KeySet
	// Leeway absorbs clock skew between the issuer and this server. It is
	// deliberately small: a generous leeway is an expired token that still
	// works, which is the thing expiry exists to prevent.
	Leeway time.Duration
	// TenantID for the MVP's single tenant.
	TenantID string
}

// KeySet resolves a key id to a public key.
type KeySet interface {
	Key(kid string) (any, error)
}

// Claims is the subset of a token this server reads. Anything not named here
// is ignored: a claim the server does not understand cannot be a claim the
// server relies on.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	Scopes    string   `json:"scope"`
	// PrincipalID is a Sentinel claim mapping the subject onto a row in
	// `principals`. In a fuller deployment this would be a lookup rather than a
	// claim; the MVP has a static issuer and two principals.
	PrincipalID string `json:"principal_id"`
}

// GetExpirationTime and friends satisfy jwt.Claims. Validation of iss, aud and
// exp is done explicitly in Validate rather than through the library's options,
// so the comparisons are visible in this file rather than configured elsewhere.
func (c Claims) GetExpirationTime() (*jwt.NumericDate, error) { return numeric(c.ExpiresAt), nil }
func (c Claims) GetIssuedAt() (*jwt.NumericDate, error)       { return numeric(c.IssuedAt), nil }
func (c Claims) GetNotBefore() (*jwt.NumericDate, error)      { return numeric(c.NotBefore), nil }
func (c Claims) GetIssuer() (string, error)                   { return c.Issuer, nil }
func (c Claims) GetSubject() (string, error)                  { return c.Subject, nil }
func (c Claims) GetAudience() (jwt.ClaimStrings, error)       { return jwt.ClaimStrings(c.Audience), nil }

func numeric(sec int64) *jwt.NumericDate {
	if sec == 0 {
		return nil
	}
	return jwt.NewNumericDate(time.Unix(sec, 0))
}

// Validate is the only function in this repository that turns a token into a
// principal.
//
// The order matters less than the completeness, but signature first is still
// right: nothing in an unverified token is worth reading, including its
// audience.
func Validate(tokenString string, cfg Config, now time.Time) (registry.Principal, error) {
	if tokenString == "" {
		return registry.Principal{}, ErrMalformed
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "EdDSA"}),
		// The library's own claim validation is switched off. Every check this
		// server relies on is written below, in this file, where §5 says it
		// should be auditable.
		jwt.WithoutClaimsValidation(),
	)

	var claims Claims
	_, err := parser.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return cfg.Keys.Key(kid)
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return registry.Principal{}, ErrMalformed
		}
		return registry.Principal{}, ErrUnauthenticated
	}

	// THE check. Exact membership of the audience list.
	//
	// containsExact, not strings.HasPrefix and not strings.Contains: an audience
	// of "https://broker.sentinel.local" must not be satisfied by
	// "https://broker.sentinel.local.evil.example", which a prefix match accepts
	// and which is a real attack rather than a hypothetical one.
	if !containsExact(claims.Audience, cfg.Audience) {
		return registry.Principal{}, ErrWrongAudience
	}

	if claims.Issuer != cfg.Issuer {
		return registry.Principal{}, ErrWrongIssuer
	}

	if claims.ExpiresAt == 0 {
		// A token with no expiry never stops working. Refusing it is the only
		// safe reading; treating it as "valid forever" is the unsafe one.
		return registry.Principal{}, ErrExpired
	}
	if now.Add(-cfg.Leeway).After(time.Unix(claims.ExpiresAt, 0)) {
		return registry.Principal{}, ErrExpired
	}
	if claims.NotBefore != 0 && now.Add(cfg.Leeway).Before(time.Unix(claims.NotBefore, 0)) {
		return registry.Principal{}, ErrUnauthenticated
	}

	if claims.PrincipalID == "" {
		return registry.Principal{}, ErrUnauthenticated
	}

	return registry.Principal{
		TenantID: cfg.TenantID,
		ID:       claims.PrincipalID,
		Scopes:   ParseScopes(claims.Scopes),
		// The token itself is deliberately NOT carried onto the Principal.
		// registry.Principal has no field for it, so there is nothing for a
		// downstream call to forward even by accident — see outbound.go.
	}, nil
}

// containsExact reports exact string membership.
func containsExact(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// StaticKeySet is a JWKS loaded from a file. Full OAuth discovery is out of
// scope (§3.2); the audience MUST NOT is not.
type StaticKeySet struct {
	keys map[string]any
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// LoadKeySet reads a JWKS from disk.
func LoadKeySet(path string) (*StaticKeySet, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // an operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("authz: read jwks: %w", err)
	}
	return ParseKeySet(raw)
}

// ParseKeySet builds a key set from JWKS bytes.
func ParseKeySet(raw []byte) (*StaticKeySet, error) {
	var set jwkSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("authz: parse jwks: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("authz: jwks contains no keys")
	}

	out := &StaticKeySet{keys: make(map[string]any, len(set.Keys))}
	for _, k := range set.Keys {
		key, err := decodeJWK(k)
		if err != nil {
			return nil, err
		}
		out.keys[k.Kid] = key
	}
	return out, nil
}

func decodeJWK(k jwk) (any, error) {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("authz: jwk %q: bad modulus: %w", k.Kid, err)
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("authz: jwk %q: bad exponent: %w", k.Kid, err)
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("authz: jwk %q: unsupported curve %q", k.Kid, k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("authz: jwk %q: bad key: %w", k.Kid, err)
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("authz: jwk %q: key is %d bytes, want %d",
				k.Kid, len(x), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("authz: jwk %q: unsupported key type %q", k.Kid, k.Kty)
	}
}

// Key resolves a key id.
//
// An unknown kid is an error rather than "try them all". Trying every key turns
// a key rotation mistake into a silent acceptance, and it lets a token minted
// for one key id be verified by another.
func (s *StaticKeySet) Key(kid string) (any, error) {
	if kid == "" {
		if len(s.keys) == 1 {
			for _, k := range s.keys {
				return k, nil
			}
		}
		return nil, errors.New("authz: token has no kid and the key set is ambiguous")
	}
	key, ok := s.keys[kid]
	if !ok {
		return nil, fmt.Errorf("authz: no key with id %q", kid)
	}
	return key, nil
}
