package authz

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	thisServer  = "https://broker.sentinel.local"
	otherServer = "https://billing.sentinel.local"
	issuer      = "https://issuer.sentinel.local"
	tenant      = "00000000-0000-0000-0000-000000000001"
	principalID = "00000000-0000-0000-0000-0000000000a1"
	testKid     = "test-key-1"
)

type signer struct {
	priv ed25519.PrivateKey
	keys *StaticKeySet
}

func newSigner(t *testing.T) *signer {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jwkSet{Keys: []jwk{{
		Kty: "OKP", Kid: testKid, Alg: "EdDSA", Use: "sig", Crv: "Ed25519",
		X: base64.RawURLEncoding.EncodeToString(pub),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseKeySet(jwks)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{priv: priv, keys: keys}
}

// mint produces a structurally valid, correctly signed token. Every negative
// test below differs from a good token in exactly one respect, so a failure
// names the property that broke.
func (s *signer) mint(t *testing.T, mutate func(*Claims)) string {
	t.Helper()

	claims := Claims{
		Issuer:      issuer,
		Subject:     "analyst@acme.example",
		Audience:    []string{thisServer},
		ExpiresAt:   time.Now().Add(time.Hour).Unix(),
		IssuedAt:    time.Now().Unix(),
		Scopes:      "warehouse:read warehouse:describe",
		PrincipalID: principalID,
	}
	if mutate != nil {
		mutate(&claims)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = testKid
	signed, err := token.SignedString(s.priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (s *signer) config() Config {
	return Config{
		Issuer:   issuer,
		Audience: thisServer,
		Keys:     s.keys,
		Leeway:   30 * time.Second,
		TenantID: tenant,
	}
}

func TestValidTokenBecomesAPrincipal(t *testing.T) {
	s := newSigner(t)

	p, err := Validate(s.mint(t, nil), s.config(), time.Now())
	if err != nil {
		t.Fatalf("a valid token was rejected: %v", err)
	}
	if p.ID != principalID {
		t.Fatalf("principal id = %q", p.ID)
	}
	if p.TenantID != tenant {
		t.Fatalf("tenant = %q", p.TenantID)
	}
	if !p.HasScope("warehouse:read") {
		t.Fatalf("scopes = %v", p.Scopes)
	}
}

// TestTokenForAnotherAudienceRejected — one of the nine negative tests of §11,
// and the specification's explicit MUST NOT.
//
// The token is structurally valid and CORRECTLY SIGNED BY THE SAME ISSUER. The
// only thing wrong with it is that it was issued for a different service, which
// is exactly the token an attacker who compromised that service would hold.
func TestTokenForAnotherAudienceRejected(t *testing.T) {
	s := newSigner(t)

	token := s.mint(t, func(c *Claims) { c.Audience = []string{otherServer} })

	if _, err := Validate(token, s.config(), time.Now()); !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("err = %v, want ErrWrongAudience: MCP servers MUST NOT accept any token "+
			"not explicitly issued for the MCP server", err)
	}
}

// TestAudienceMatchIsExactNotPrefix. Each of these is accepted by a plausible
// but wrong implementation — HasPrefix, Contains, or a normalizing compare.
func TestAudienceMatchIsExactNotPrefix(t *testing.T) {
	s := newSigner(t)

	nearMisses := []string{
		thisServer + ".evil.example",    // HasPrefix accepts this
		thisServer + "/",                // a trailing slash
		"evil.example/" + thisServer,    // Contains accepts this
		"https://BROKER.sentinel.local", // case
		"http://broker.sentinel.local",  // scheme
		"https://broker.sentinel.local:8443",
		" " + thisServer, // leading whitespace
		thisServer + " ",
	}

	for _, aud := range nearMisses {
		t.Run(aud, func(t *testing.T) {
			token := s.mint(t, func(c *Claims) { c.Audience = []string{aud} })
			if _, err := Validate(token, s.config(), time.Now()); !errors.Is(err, ErrWrongAudience) {
				t.Fatalf("audience %q was accepted for %q (err = %v); the comparison must be "+
					"exact string equality", aud, thisServer, err)
			}
		})
	}
}

// TestMultiAudienceTokenIsAcceptedOnlyByExactMembership. A token legitimately
// issued for several services is valid here if and only if this server is one
// of them.
func TestMultiAudienceTokenIsAcceptedOnlyByExactMembership(t *testing.T) {
	s := newSigner(t)

	included := s.mint(t, func(c *Claims) {
		c.Audience = []string{otherServer, thisServer, "https://third.example"}
	})
	if _, err := Validate(included, s.config(), time.Now()); err != nil {
		t.Fatalf("a token listing this server among its audiences was rejected: %v", err)
	}

	excluded := s.mint(t, func(c *Claims) {
		c.Audience = []string{otherServer, "https://third.example"}
	})
	if _, err := Validate(excluded, s.config(), time.Now()); !errors.Is(err, ErrWrongAudience) {
		t.Fatal("a token not listing this server was accepted")
	}
}

func TestEmptyAudienceRejected(t *testing.T) {
	s := newSigner(t)

	for _, aud := range [][]string{nil, {}, {""}} {
		token := s.mint(t, func(c *Claims) { c.Audience = aud })
		if _, err := Validate(token, s.config(), time.Now()); !errors.Is(err, ErrWrongAudience) {
			t.Errorf("audience %v was accepted", aud)
		}
	}
}

func TestWrongIssuerRejected(t *testing.T) {
	s := newSigner(t)

	token := s.mint(t, func(c *Claims) { c.Issuer = "https://issuer.evil.example" })
	if _, err := Validate(token, s.config(), time.Now()); !errors.Is(err, ErrWrongIssuer) {
		t.Fatalf("err = %v, want ErrWrongIssuer", err)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	s := newSigner(t)

	token := s.mint(t, func(c *Claims) { c.ExpiresAt = time.Now().Add(-time.Hour).Unix() })
	if _, err := Validate(token, s.config(), time.Now()); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

// TestTokenWithNoExpiryRejected. A token with no expiry never stops working.
// Treating a missing `exp` as "valid forever" is the unsafe reading.
func TestTokenWithNoExpiryRejected(t *testing.T) {
	s := newSigner(t)

	token := s.mint(t, func(c *Claims) { c.ExpiresAt = 0 })
	if _, err := Validate(token, s.config(), time.Now()); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired: a token with no expiry never stops working", err)
	}
}

// TestLeewayIsSmall. A generous leeway is an expired token that still works.
func TestLeewayAbsorbsSkewButNotStaleness(t *testing.T) {
	s := newSigner(t)
	cfg := s.config() // 30s leeway

	justExpired := s.mint(t, func(c *Claims) { c.ExpiresAt = time.Now().Add(-10 * time.Second).Unix() })
	if _, err := Validate(justExpired, cfg, time.Now()); err != nil {
		t.Fatalf("a token expired 10s ago was rejected under 30s of leeway: %v", err)
	}

	longExpired := s.mint(t, func(c *Claims) { c.ExpiresAt = time.Now().Add(-10 * time.Minute).Unix() })
	if _, err := Validate(longExpired, cfg, time.Now()); !errors.Is(err, ErrExpired) {
		t.Fatal("a token expired ten minutes ago was accepted; leeway is for clock skew, " +
			"not for staleness")
	}
}

// TestTokenSignedByAnotherKeyRejected. The claims are perfect; only the
// signature is another party's.
func TestTokenSignedByAnotherKeyRejected(t *testing.T) {
	ours, theirs := newSigner(t), newSigner(t)

	token := theirs.mint(t, nil)
	if _, err := Validate(token, ours.config(), time.Now()); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrUnauthenticated", err)
	}
}

// TestUnsignedTokenRejected. `alg: none` is the oldest JWT attack there is, and
// it works against any parser that trusts the header.
func TestUnsignedTokenRejected(t *testing.T) {
	s := newSigner(t)

	claims := Claims{
		Issuer: issuer, Audience: []string{thisServer},
		ExpiresAt: time.Now().Add(time.Hour).Unix(), PrincipalID: principalID,
	}
	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	unsigned.Header["kid"] = testKid
	token, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Validate(token, s.config(), time.Now()); err == nil {
		t.Fatal("an alg:none token was accepted")
	}
}

func TestMalformedTokenRejected(t *testing.T) {
	s := newSigner(t)

	for _, token := range []string{"", "not.a.token", "a.b", "....", "Bearer abc"} {
		if _, err := Validate(token, s.config(), time.Now()); err == nil {
			t.Errorf("malformed token %q was accepted", token)
		}
	}
}

// TestUnknownKeyIDIsRefusedRatherThanSearched. Trying every key turns a
// rotation mistake into a silent acceptance.
func TestUnknownKeyIDIsRefusedRatherThanSearched(t *testing.T) {
	s := newSigner(t)

	claims := Claims{
		Issuer: issuer, Audience: []string{thisServer},
		ExpiresAt: time.Now().Add(time.Hour).Unix(), PrincipalID: principalID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = "a-key-we-have-never-seen"
	signed, err := token.SignedString(s.priv)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Validate(signed, s.config(), time.Now()); err == nil {
		t.Fatal("a token naming an unknown key id was accepted")
	}
}

// TestPrincipalCarriesNoToken. The structural half of the passthrough ban: by
// the time a handler runs there is no variable holding the inbound token, so
// there is nothing to forward even by accident.
func TestPrincipalCarriesNoToken(t *testing.T) {
	s := newSigner(t)
	token := s.mint(t, nil)

	p, err := Validate(token, s.config(), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Reflection over the whole struct, so a field ADDED later is caught rather
	// than a named field being absent today.
	rendered, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if containsSubstring(string(rendered), token) {
		t.Fatalf("the principal carries the inbound token: %s", rendered)
	}
	for _, suspicious := range []string{"token", "Token", "bearer", "Bearer", "credential"} {
		if containsSubstring(string(rendered), suspicious) {
			t.Fatalf("the principal has a field that looks like it holds a credential (%q): %s",
				suspicious, rendered)
		}
	}
}

func TestScopeParsing(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"a", 1},
		{"a b c", 3},
		{"a,b,c", 3},
		{"  a   b  ", 2},
		{"a\tb", 2},
	}
	for _, c := range cases {
		if got := ParseScopes(c.in); len(got) != c.want {
			t.Errorf("ParseScopes(%q) = %v, want %d scopes", c.in, got, c.want)
		}
	}
	if ParseScopes("") == nil {
		t.Error("ParseScopes must return an empty slice, never nil: \"no scopes\" is a " +
			"determination, nil reads as \"not determined\"")
	}
}

// TestWireErrorDoesNotDistinguishFailureModes. Which check a token failed is
// useful in a log and an oracle on the wire.
func TestWireErrorDoesNotDistinguishFailureModes(t *testing.T) {
	s := newSigner(t)
	cfg := s.config()

	wrongAudience := RPCError(cfg)
	expired := RPCError(cfg)

	if wrongAudience.Code != expired.Code || wrongAudience.Message != expired.Message {
		t.Fatal("the wire error varies by failure mode, which tells a caller probing with a " +
			"token which check to work around next")
	}
	if wrongAudience.Data != nil {
		t.Fatal("the wire error must carry no data field")
	}
	// It should still say what this server DOES accept: those are published
	// facts, and withholding them only obstructs the honest client.
	if !containsSubstring(wrongAudience.Message, thisServer) ||
		!containsSubstring(wrongAudience.Message, issuer) {
		t.Fatalf("the message should name the accepted issuer and audience: %q",
			wrongAudience.Message)
	}
}

func containsSubstring(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
