// Package transport carries MCP over Streamable HTTP POST and over stdio. Both
// are thin adapters over one dispatch path, which is a useful forcing function
// against transport-specific state creeping back in.
package transport

import (
	"context"
	"encoding/json"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
)

// Handler serves one MCP method. It returns a Result — an interface satisfiable
// only by embedding envelope.Base — so a handler structurally cannot return
// something that skipped the envelope.
type Handler func(ctx context.Context, params json.RawMessage) (envelope.Result, *envelope.RPCError)

// removedMethod records a method the 2026-07-28 revision deleted.
//
// §9.1: these must return method-not-found rather than being silently absent
// from the router. The distinction matters to a migrating client — a routed
// method-not-found carrying the revision that removed it and its replacement is
// actionable; a 404 from an unknown path is not. A conformance rule checks
// exactly this, so the broker must satisfy its own harness.
type removedMethod struct {
	removedIn   string
	replacement string
}

var removedMethods = map[string]removedMethod{
	"ping":                             {removedIn: "2026-07-28"},
	"initialize":                       {removedIn: "2026-07-28", replacement: "server/discover"},
	"logging/setLevel":                 {removedIn: "2026-07-28", replacement: "_meta." + envelope.KeyLogLevel},
	"notifications/roots/list_changed": {removedIn: "2026-07-28"},
	"resources/subscribe":              {removedIn: "2026-07-28", replacement: "subscriptions/listen"},
	"resources/unsubscribe":            {removedIn: "2026-07-28", replacement: "subscriptions/listen"},
	"sampling/createMessage":           {removedIn: "2026-07-28", replacement: "multi round-trip requests"},
	"roots/list":                       {removedIn: "2026-07-28"},
}

// Mux routes methods to handlers.
type Mux struct {
	handlers map[string]Handler
}

func NewMux() *Mux { return &Mux{handlers: make(map[string]Handler)} }

// Handle registers a handler. Registering a removed method panics: it would
// make the server fail its own conformance harness, and that is better caught
// at boot than in front of an audience.
func (m *Mux) Handle(method string, h Handler) {
	if _, gone := removedMethods[method]; gone {
		panic("transport: refusing to register " + method + ", which was removed in 2026-07-28")
	}
	m.handlers[method] = h
}

// Lookup resolves a method to a handler, or to the error explaining why there
// is none.
func (m *Mux) Lookup(method string) (Handler, *envelope.RPCError) {
	if h, ok := m.handlers[method]; ok {
		return h, nil
	}
	if gone, ok := removedMethods[method]; ok {
		return nil, envelope.ErrMethodRemoved(method, gone.removedIn, gone.replacement)
	}
	return nil, envelope.ErrMethodNotFound(method)
}

// Methods lists every registered method. Used by the header contract to decide
// whether Mcp-Name should name a tool or repeat the method.
func (m *Mux) Methods() []string {
	out := make([]string, 0, len(m.handlers))
	for k := range m.handlers {
		out = append(out, k)
	}
	return out
}

// IsRemovedMethod reports whether a method was deleted by this revision.
func IsRemovedMethod(method string) bool {
	_, ok := removedMethods[method]
	return ok
}
