package authz

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder captures every outbound request a downstream service receives, in
// full — headers, query and body — so a token that leaked into ANY of them is
// caught, not just one that leaked into Authorization.
type recorder struct {
	mu       sync.Mutex
	requests []string
	server   *httptest.Server
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()

	r := &recorder{}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)

		var sb strings.Builder
		sb.WriteString(req.Method + " " + req.URL.String() + "\n")
		for name, values := range req.Header {
			for _, v := range values {
				sb.WriteString(name + ": " + v + "\n")
			}
		}
		sb.Write(body)

		r.mu.Lock()
		r.requests = append(r.requests, sb.String())
		r.mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.requests...)
}

// TestInboundTokenNeverForwarded — one of the nine negative tests of §11, and
// the one §8.6 says "actually catches the bug, because forwarding a token feels
// helpful when you write it."
//
// The scenario is complete: a real inbound token is validated, a principal is
// derived from it, and while serving that principal the broker makes a
// downstream call. Every byte the downstream service received is then searched
// for the inbound token.
func TestInboundTokenNeverForwarded(t *testing.T) {
	s := newSigner(t)
	inbound := s.mint(t, nil)

	principal, err := Validate(inbound, s.config(), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	downstream := newRecorder(t)
	client := NewClient(StaticCredential{Value: "the-brokers-own-credential"}, 5*time.Second)

	// Serve a call on this principal's behalf: three downstream requests,
	// carrying data derived from the principal, as a real handler would.
	for _, path := range []string{"/warehouse/query", "/warehouse/schema", "/audit/emit"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			downstream.server.URL+path,
			strings.NewReader(`{"principal":"`+principal.ID+`","scopes":"`+
				strings.Join(principal.Scopes, " ")+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}

	captured := downstream.all()
	if len(captured) != 3 {
		t.Fatalf("captured %d downstream requests, want 3", len(captured))
	}

	for i, req := range captured {
		if strings.Contains(req, inbound) {
			t.Fatalf("downstream request %d carries the INBOUND token:\n%s", i, req)
		}
		// Also check the token's parts. A handler that split the token, or
		// forwarded only its payload, would defeat a whole-string search.
		for _, part := range strings.Split(inbound, ".") {
			if len(part) > 16 && strings.Contains(req, part) {
				t.Fatalf("downstream request %d carries a fragment of the inbound token "+
					"(%.16s…):\n%s", i, part, req)
			}
		}
		// And the broker's own credential must be there, or the test proved
		// nothing about forwarding — it would pass equally against a client
		// that sent no credential at all.
		if !strings.Contains(req, "the-brokers-own-credential") {
			t.Fatalf("downstream request %d carries no credential at all, so this test "+
				"cannot distinguish 'did not forward' from 'sent nothing':\n%s", i, req)
		}
	}
}

// TestOutboundClientOverwritesAnyPresetAuthorization. The belt to the
// structural braces: even a caller who found a token and set the header by hand
// does not get it past this function.
func TestOutboundClientOverwritesAnyPresetAuthorization(t *testing.T) {
	downstream := newRecorder(t)
	client := NewClient(StaticCredential{Value: "the-brokers-own-credential"}, 5*time.Second)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		downstream.server.URL+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer a-token-somebody-set-by-hand")

	resp, err := client.Do(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	captured := downstream.all()[0]
	if strings.Contains(captured, "a-token-somebody-set-by-hand") {
		t.Fatalf("a hand-set Authorization header survived:\n%s", captured)
	}
	if !strings.Contains(captured, "the-brokers-own-credential") {
		t.Fatalf("the server's own credential was not attached:\n%s", captured)
	}
}

// TestCredentialTakesNoPrincipal. The interface itself refuses the shape that
// would make forwarding natural: a credential that varied by caller is an
// invitation to pass one through.
func TestCredentialTakesNoPrincipal(t *testing.T) {
	// This is a compile-time property, asserted by the fact that this file
	// compiles: Credential.Token(ctx) has no principal parameter and no token
	// parameter. The test exists so the property is named somewhere a reader
	// will find it.
	var c Credential = StaticCredential{Value: "x"}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestMissingCredentialIsAnErrorNotAnAnonymousCall(t *testing.T) {
	downstream := newRecorder(t)
	client := NewClient(StaticCredential{}, 5*time.Second)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		downstream.server.URL+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(context.Background(), req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("an unconfigured credential produced an anonymous downstream call; it must " +
			"be an error, or a misconfiguration becomes a silent privilege change")
	}
	if len(downstream.all()) != 0 {
		t.Fatal("a request was sent despite there being no credential")
	}
}
