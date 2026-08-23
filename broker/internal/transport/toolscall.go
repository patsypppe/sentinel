package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/handles"
	"github.com/patsypppe/sentinel/broker/internal/mrtr"
	"github.com/patsypppe/sentinel/broker/internal/registry"
)

// Authenticator turns a request into a validated principal.
//
// WP-7 supplies the real implementation, which validates a token's audience and
// is the ONLY place a token is accepted. The interface exists now so the
// transport is already shaped for it and the swap is one line.
type Authenticator interface {
	Authenticate(r *http.Request) (registry.Principal, *envelope.RPCError)
}

// ToolLookup is the registry surface tools/call needs.
type ToolLookup interface {
	Lookup(name string) (registry.Tool, bool)
}

type principalKey struct{}

// WithPrincipal attaches the authenticated principal to a context.
func WithPrincipal(ctx context.Context, p registry.Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the authenticated principal.
func PrincipalFrom(ctx context.Context) (registry.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(registry.Principal)
	return p, ok
}

type toolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ToolsCallHandler dispatches to a registered tool.
//
// Scope enforcement happens here rather than inside each tool, so a tool cannot
// forget it. The tool still declares which scopes it needs — that is one of the
// six mandatory properties — but it does not get to decide whether they are
// checked.
func ToolsCallHandler(reg ToolLookup) Handler {
	return func(ctx context.Context, raw json.RawMessage) (envelope.Result, *envelope.RPCError) {
		var params toolsCallParams
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &params); err != nil {
				return nil, envelope.ErrInvalidParams("params", err.Error(), "must be an object")
			}
		}
		if params.Name == "" {
			return nil, envelope.ErrInvalidParams("name", "",
				"is required; try {\"name\":\"warehouse.query\",\"arguments\":{...}}")
		}

		tool, ok := reg.Lookup(params.Name)
		if !ok {
			return nil, envelope.New(envelope.CodeInvalidParams,
				fmt.Sprintf("no such tool %q; call tools/list for the current manifest", params.Name),
				nil)
		}

		p, ok := PrincipalFrom(ctx)
		if !ok {
			return nil, envelope.ErrInternal("no authenticated principal on the request")
		}

		// Every declared scope, exactly. The refusal names the missing scope so
		// the caller can request it rather than guess.
		for _, want := range tool.Scopes() {
			if !p.HasScope(want) {
				return nil, envelope.New(envelope.CodeScopeDenied,
					fmt.Sprintf("%q requires the %q scope, which this principal does not hold",
						tool.Name(), want),
					struct {
						RequiredScope string `json:"requiredScope"`
					}{RequiredScope: want})
			}
		}

		result, err := tool.Call(ctx, p, params.Arguments)
		if err != nil {
			return nil, toolError(err)
		}
		return result, nil
	}
}

// toolError maps a tool's error onto the wire.
//
// The sentinel errors are checked before the fallback so that a handle refusal
// and an MRTR refusal keep their specific, actionable codes. Everything else
// becomes a -32602: a tool that returns a bare error is reporting bad input,
// and an internal error would be both less accurate and less useful.
func toolError(err error) *envelope.RPCError {
	switch {
	case errors.Is(err, handles.ErrNotResolvable):
		return handles.RPCError()
	case errors.Is(err, mrtr.ErrStateInvalid),
		errors.Is(err, mrtr.ErrStateExpired),
		errors.Is(err, mrtr.ErrFlowExpired),
		errors.Is(err, mrtr.ErrArgumentsMutated),
		errors.Is(err, mrtr.ErrReplayWindowClosed),
		errors.Is(err, mrtr.ErrFlowNotFound):
		return mrtr.RPCError(err)
	default:
		return envelope.New(envelope.CodeInvalidParams, err.Error(), nil)
	}
}

// DevAuthenticator reads a principal from headers. It exists ONLY until WP-7
// wires audience validation, and it refuses to run unless explicitly enabled,
// so it cannot become production behaviour by omission.
//
// It is not a fallback and not a default: an unset BROKER_DEV_AUTH means every
// request is refused, which is the correct failure mode for an authentication
// layer that has not been configured.
type DevAuthenticator struct {
	Enabled bool
	Tenant  string
}

// HeaderPrincipal and HeaderScopes are the dev-mode inputs.
const (
	HeaderPrincipal = "X-Sentinel-Dev-Principal"
	HeaderScopes    = "X-Sentinel-Dev-Scopes"
)

func (d DevAuthenticator) Authenticate(r *http.Request) (registry.Principal, *envelope.RPCError) {
	if !d.Enabled {
		return registry.Principal{}, envelope.New(envelope.CodeInvalidRequest,
			"this server has no authentication configured and refuses every request; "+
				"set BROKER_OAUTH_JWKS_PATH, or BROKER_DEV_AUTH=1 for local development", nil)
	}
	id := r.Header.Get(HeaderPrincipal)
	if id == "" {
		return registry.Principal{}, envelope.New(envelope.CodeInvalidRequest,
			"dev authentication is enabled but "+HeaderPrincipal+" is absent", nil)
	}
	return registry.Principal{
		TenantID: d.Tenant,
		ID:       id,
		Scopes:   splitScopes(r.Header.Get(HeaderScopes)),
	}, nil
}

func splitScopes(raw string) []string {
	// An explicitly empty slice, never nil: "no scopes" is a decision, and nil
	// reads as "not determined".
	scopes := []string{}
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == ' ' || raw[i] == ',' {
			if i > start {
				scopes = append(scopes, raw[start:i])
			}
			start = i + 1
		}
	}
	return scopes
}
