package authz

import (
	"net/http"
	"testing"
	"time"
)

func request(t *testing.T, header string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "http://localhost:8080/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	return r
}

func TestAuthenticateAcceptsAValidBearerToken(t *testing.T) {
	s := newSigner(t)
	auth := NewTokenAuthenticator(s.config())

	p, rpcErr := auth.Authenticate(request(t, "Bearer "+s.mint(t, nil)))
	if rpcErr != nil {
		t.Fatalf("a valid token was refused: %d %s", rpcErr.Code, rpcErr.Message)
	}
	if p.ID != principalID {
		t.Fatalf("principal = %q", p.ID)
	}
}

func TestBearerSchemeIsCaseInsensitiveButTheTokenIsNot(t *testing.T) {
	s := newSigner(t)
	auth := NewTokenAuthenticator(s.config())
	token := s.mint(t, nil)

	// RFC 7235: the scheme is case-insensitive.
	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr"} {
		if _, err := auth.Authenticate(request(t, scheme+" "+token)); err != nil {
			t.Errorf("scheme %q was refused; the scheme is case-insensitive", scheme)
		}
	}

	// The token is not. Changing its case invalidates the signature.
	if _, err := auth.Authenticate(request(t, "Bearer "+upperFirst(token))); err == nil {
		t.Error("a token whose case was changed was accepted")
	}
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'a' && b[0] <= 'z' {
		b[0] -= 32
	} else if b[0] >= 'A' && b[0] <= 'Z' {
		b[0] += 32
	}
	return string(b)
}

// TestEveryAuthenticationFailureLooksTheSame. The wire must not say which check
// failed.
func TestEveryAuthenticationFailureLooksTheSame(t *testing.T) {
	s := newSigner(t)
	auth := NewTokenAuthenticator(s.config())
	other := newSigner(t)

	headers := map[string]string{
		"absent":             "",
		"no scheme":          s.mint(t, nil),
		"wrong scheme":       "Basic " + s.mint(t, nil),
		"empty token":        "Bearer ",
		"malformed":          "Bearer not.a.token",
		"wrong audience":     "Bearer " + s.mint(t, func(c *Claims) { c.Audience = []string{otherServer} }),
		"wrong issuer":       "Bearer " + s.mint(t, func(c *Claims) { c.Issuer = "https://evil.example" }),
		"expired":            "Bearer " + s.mint(t, func(c *Claims) { c.ExpiresAt = 1 }),
		"another key":        "Bearer " + other.mint(t, nil),
		"no principal claim": "Bearer " + s.mint(t, func(c *Claims) { c.PrincipalID = "" }),
	}

	var first *string
	for desc, header := range headers {
		_, rpcErr := auth.Authenticate(request(t, header))
		if rpcErr == nil {
			t.Fatalf("%s was accepted", desc)
		}
		rendered := rpcErr.Message
		if first == nil {
			first = &rendered
			continue
		}
		if rendered != *first {
			t.Fatalf("%s produced a different message, which tells a caller which check to "+
				"work around next:\n %q\n %q", desc, *first, rendered)
		}
	}
}

func TestBearerTokenParsing(t *testing.T) {
	cases := []struct {
		header string
		want   string
		ok     bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"Bearer  abc  ", "abc", true},
		{"Basic abc", "", false},
		{"abc", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := bearerToken(c.header)
		if ok != c.ok || got != c.want {
			t.Errorf("bearerToken(%q) = (%q, %v), want (%q, %v)", c.header, got, ok, c.want, c.ok)
		}
	}
}

func TestAuthenticatorUsesItsOwnClock(t *testing.T) {
	s := newSigner(t)
	auth := NewTokenAuthenticator(s.config())
	token := s.mint(t, nil) // expires in an hour

	auth.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := auth.Authenticate(request(t, "Bearer "+token)); err == nil {
		t.Fatal("a token expired relative to the authenticator's clock was accepted")
	}
}
