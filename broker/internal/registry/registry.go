// Package registry owns tool registration and the deterministic manifest.
//
// A tool cannot exist without declaring all six properties of docs/HANDOFF.md
// §7.3. That is enforced by the interface rather than by a review checklist:
// there is no way to register something that has not answered every question,
// and Reversibility in particular means a new tool cannot skip deciding whether
// it needs an MRTR confirmation.
package registry

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
)

// Reversibility rates a tool by how recoverable its effect is. It drives
// whether a call requires an MRTR confirmation, so putting it in the type
// system means a new tool cannot skip the question.
type Reversibility string

const (
	// Reversible: no confirmation. Read-only or trivially undone.
	Reversible Reversibility = "reversible"
	// Recoverable: confirmation above a configured threshold. The effect can be
	// undone, but not for free.
	Recoverable Reversibility = "recoverable"
	// Irreversible: ALWAYS confirmed through MRTR, with no threshold and no
	// exception.
	Irreversible Reversibility = "irreversible"
)

func (r Reversibility) valid() bool {
	switch r {
	case Reversible, Recoverable, Irreversible:
		return true
	}
	return false
}

// RequiresConfirmation reports whether a call must go through an MRTR
// input_required round trip before its effect happens.
func (r Reversibility) RequiresConfirmation(aboveThreshold bool) bool {
	switch r {
	case Irreversible:
		return true
	case Recoverable:
		return aboveThreshold
	default:
		return false
	}
}

// Principal is the authenticated caller. It is derived from a validated token
// on every request — there is no session, and nothing here is cached.
type Principal struct {
	TenantID string
	ID       string
	Scopes   []string
	// Token is deliberately absent. The inbound token is never carried past
	// authz and never forwarded downstream (§8.6).
}

// HasScope reports exact membership. Never a prefix match.
func (p Principal) HasScope(want string) bool {
	for _, s := range p.Scopes {
		if s == want {
			return true
		}
	}
	return false
}

// Result is what a tool returns.
type Result = *envelope.ToolsCallResult

// Tool is the six-property contract. Every method is mandatory; there is no
// embeddable default, because a default is how a tool skips a decision.
type Tool interface {
	// Name is namespaced, e.g. "warehouse.query".
	Name() string
	// Description is read by a model, so it is part of the interface.
	Description() string
	// InputSchema is JSON Schema 2020-12.
	InputSchema() json.RawMessage
	// OutputSchema is JSON Schema 2020-12.
	OutputSchema() json.RawMessage
	// Scopes the principal must hold, all of them.
	Scopes() []string
	// Reversibility drives MRTR confirmation.
	Reversibility() Reversibility
	// CachePolicy for this tool's results.
	CachePolicy() envelope.CachePolicy
	// TokenCap is a hard ceiling on response tokens. Exceeding it does not
	// truncate: the tool returns a handle to the full result plus a summary.
	TokenCap() int

	Call(ctx context.Context, p Principal, args json.RawMessage) (Result, error)
}

// Registry holds the registered tools and the manifest built from them.
//
// The manifest is built ONCE at construction. tools/list serves the
// precomputed bytes: re-serializing per request is both wasteful and the place
// determinism usually dies (§9.2).
type Registry struct {
	tools    map[string]Tool
	ordered  []Tool
	manifest []byte
	hash     string
	tokens   TokenCount
}

// New validates and registers tools, then builds the manifest.
func New(tools ...Tool) (*Registry, error) {
	r := &Registry{tools: make(map[string]Tool, len(tools))}

	for _, t := range tools {
		if err := validate(t); err != nil {
			return nil, err
		}
		if _, dup := r.tools[t.Name()]; dup {
			return nil, fmt.Errorf("registry: %q is registered twice", t.Name())
		}
		r.tools[t.Name()] = t
	}

	if err := r.build(); err != nil {
		return nil, err
	}
	return r, nil
}

func validate(t Tool) error {
	name := t.Name()
	if name == "" {
		return fmt.Errorf("registry: a tool declared an empty name")
	}
	if t.Description() == "" {
		return fmt.Errorf("registry: %q declares no description; a model reads it, so it is part of the interface", name)
	}
	if len(t.InputSchema()) == 0 {
		return fmt.Errorf("registry: %q declares no input schema", name)
	}
	if len(t.OutputSchema()) == 0 {
		return fmt.Errorf("registry: %q declares no output schema", name)
	}
	if t.Scopes() == nil {
		return fmt.Errorf("registry: %q declares nil scopes; an explicitly empty slice means "+
			"\"no scope required\" and is a different claim from having not decided", name)
	}
	if !t.Reversibility().valid() {
		return fmt.Errorf("registry: %q declares reversibility %q; must be one of reversible, "+
			"recoverable, irreversible — this decides whether the tool needs an MRTR confirmation",
			name, t.Reversibility())
	}
	if t.TokenCap() <= 0 {
		return fmt.Errorf("registry: %q declares a token cap of %d; it must be positive", name, t.TokenCap())
	}
	cp := t.CachePolicy()
	if cp.Scope != envelope.ScopePrivate && cp.Scope != envelope.ScopePublic {
		return fmt.Errorf("registry: %q declares cacheScope %q; must be private or public", name, cp.Scope)
	}
	return nil
}

// Lookup returns a registered tool.
func (r *Registry) Lookup(name string) (Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// ManifestBytes returns the precomputed canonical manifest.
func (r *Registry) ManifestBytes() []byte { return r.manifest }

// ManifestHash returns "sha256:" + hex of the canonical manifest.
func (r *Registry) ManifestHash() string { return r.hash }

// Tokens returns the manifest's measured token cost.
func (r *Registry) Tokens() TokenCount { return r.tokens }

// Len returns the number of registered tools.
func (r *Registry) Len() int { return len(r.ordered) }

// Descriptors returns the manifest entries in canonical order.
func (r *Registry) Descriptors() []envelope.ToolDescriptor {
	out := make([]envelope.ToolDescriptor, 0, len(r.ordered))
	for _, t := range r.ordered {
		out = append(out, descriptorFor(t))
	}
	return out
}
