package authz

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Outbound calls, and the MUST NOT they exist to enforce.
//
// docs/HANDOFF.md §2 rule 4: "Never forward an inbound token downstream —
// downstream calls use the server's own credential." §14 gotcha 8 notes why the
// rule needs enforcing rather than merely stating: forwarding a token FEELS
// HELPFUL when you write it. The downstream service wants to know who the user
// is; the token says who the user is; passing it along looks like plumbing.
//
// It is not plumbing. A token issued for this server, presented to another,
// makes that other service a confused deputy and makes this server the thing
// that handed it the weapon.
//
// The enforcement here is structural rather than procedural:
//
//  1. registry.Principal HAS NO TOKEN FIELD. Validate deliberately does not
//     copy the token onto it, so by the time any handler runs, the inbound
//     token is out of scope in the Go sense — there is no variable holding it.
//  2. Client takes a Credential, never a token string, and sets the
//     Authorization header itself. A caller cannot pass one through because the
//     signature does not accept one.
//
// TestInboundTokenNeverForwarded captures every outbound request made while
// serving a call and asserts the inbound token string appears in none of them.

// Credential supplies the SERVER's own downstream credential.
type Credential interface {
	// Token returns the credential to present downstream. It takes no
	// principal, deliberately: a credential that varied by caller would be an
	// invitation to pass one through.
	Token(ctx context.Context) (string, error)
}

// StaticCredential is a fixed downstream secret, which is what the MVP's static
// issuer implies. A real deployment would exchange or mint per-audience tokens
// here; the shape of the interface does not change when it does.
type StaticCredential struct {
	Value string
}

func (c StaticCredential) Token(context.Context) (string, error) {
	if c.Value == "" {
		return "", errors.New("authz: no downstream credential is configured")
	}
	return c.Value, nil
}

// Client makes downstream calls with the server's own credential.
type Client struct {
	cred Credential
	http *http.Client
}

func NewClient(cred Credential, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{cred: cred, http: &http.Client{Timeout: timeout}}
}

// Do sends a request with the server's credential attached.
//
// Any Authorization header already on the request is REPLACED, not merged.
// That is the belt to the structural braces: even if a caller found a token and
// set it by hand, it does not survive this function.
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if c.cred == nil {
		return nil, errors.New("authz: outbound client has no credential")
	}
	token, err := c.cred.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("authz: downstream credential: %w", err)
	}

	req = req.Clone(ctx)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authz: downstream request: %w", err)
	}
	return resp, nil
}
