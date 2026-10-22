// Package example is the smallest useful MCP 2026-07-28 server: one tool, no
// database, no configuration file.
//
// It is what a reader copies. `make check` builds it, serves it and scans it with
// the conformance harness, so it cannot rot: if a change to the kit makes this
// server non-conformant, the build goes red.
package example

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/patsypppe/sentinel/mcp/envelope"
	"github.com/patsypppe/sentinel/mcp/registry"
	"github.com/patsypppe/sentinel/mcp/server"
)

// Scope the single tool requires.
const Scope = "echo:call"

// Info is the server identity echoed on every result.
var Info = envelope.Info{Name: "mcp-example", Version: "0.1.0", Title: "MCP example server"}

// Reverse is the one tool: it returns its input, reversed.
//
// Every method of registry.Tool is mandatory and there is no embeddable default,
// because a default is how a tool skips a decision. Reversibility in particular
// is a question a new tool has to answer: this one only reads its arguments, so
// it is Reversible and needs no confirmation.
type Reverse struct{}

func (Reverse) Name() string { return "echo.reverse" }

func (Reverse) Description() string {
	return "Return the given text, reversed. Use it to check that a client can call a tool " +
		"and read a result."
}

func (Reverse) InputSchema() json.RawMessage {
	return json.RawMessage(`{
      "type": "object",
      "properties": {
        "text": {"type": "string", "description": "The text to reverse."}
      },
      "required": ["text"],
      "additionalProperties": false
    }`)
}

func (Reverse) OutputSchema() json.RawMessage {
	return json.RawMessage(`{
      "type": "object",
      "properties": {"reversed": {"type": "string"}},
      "required": ["reversed"]
    }`)
}

func (Reverse) Scopes() []string { return []string{Scope} }

func (Reverse) Reversibility() registry.Reversibility { return registry.Reversible }

func (Reverse) CachePolicy() envelope.CachePolicy {
	return envelope.CachePolicy{TTLMs: 0, Scope: envelope.ScopePrivate}
}

func (Reverse) TokenCap() int { return 1_000 }

func (Reverse) Call(_ context.Context, _ registry.Principal, raw json.RawMessage) (registry.Result, error) {
	var args struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("arguments could not be parsed: %w", err)
	}
	runes := []rune(args.Text)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	reversed := string(runes)
	payload, err := json.Marshal(map[string]string{"reversed": reversed})
	if err != nil {
		return nil, err
	}
	return &envelope.ToolsCallResult{
		StructuredContent: payload,
		Content:           []envelope.ContentBlock{{Type: "text", Text: reversed}},
	}, nil
}

// New builds the example server. Authentication is the explicitly insecure
// anonymous kind: this is a demonstration, and a real server replaces it.
func New() (*server.Server, error) {
	return server.New(server.Options{
		Info:         Info,
		Instructions: "A minimal example server with one tool, echo.reverse.",
		Tools:        []registry.Tool{Reverse{}},
		Authenticator: server.InsecureAnonymous(registry.Principal{
			TenantID: "example",
			ID:       "anonymous",
			Scopes:   []string{Scope},
		}),
	})
}

// Describe is a one-line summary of the manifest, for the example's startup log.
func Describe(s *server.Server) string {
	return strings.TrimSpace(fmt.Sprintf("%d tool(s), manifest %s", s.Registry().Len(), s.Registry().ManifestHash()))
}
