package transport

import (
	"context"
	"encoding/json"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
)

// DiscoverHandler answers server/discover.
//
// This is the one method that must be answerable without a negotiated version
// (§8.1) — its entire purpose is to let a client find out what versions exist
// before committing to one. envelope.Negotiate enforces the exemption; this
// handler simply has nothing version-dependent in it.
//
// Everything advertised here is true. Advertising a capability that is not
// implemented would make the broker fail its own harness, which would happen in
// front of an audience, since step 2 of the demo is scanning ourselves.
func DiscoverHandler(info envelope.Info, instructions string) Handler {
	return func(_ context.Context, _ json.RawMessage) (envelope.Result, *envelope.RPCError) {
		res := &envelope.DiscoverResult{
			ServerInfo:        info,
			SupportedVersions: []string{envelope.RevisionCurrent},
			Capabilities: envelope.Capabilities{
				// listChanged is false because subscriptions/listen is out of
				// scope for the MVP. Being truthful about that is the point:
				// a server that lies in server/discover fails its own harness.
				Tools:     envelope.ToolsCapability{ListChanged: false},
				Resources: envelope.ResourcesCapability{ListChanged: false, Subscribe: false},
				Prompts:   envelope.PromptsCapability{ListChanged: false},
			},
			// No extensions. Tasks and MCP Apps are both out of scope, and an
			// empty list is a claim we can defend.
			Extensions:   []string{},
			Instructions: instructions,
		}
		res.SetCache(envelope.DefaultDiscoverCachePolicy)
		return res, nil
	}
}

// ToolsListHandler serves the registry's PRECOMPUTED manifest bytes.
//
// §9.2: do not re-serialize per request. It is wasteful, and re-serialization
// is where determinism dies — the manifest is built once at boot, hashed once,
// and handed out unchanged until the registry reloads.
func ToolsListHandler(reg ManifestSource, policy envelope.CachePolicy) Handler {
	return func(_ context.Context, _ json.RawMessage) (envelope.Result, *envelope.RPCError) {
		res, err := reg.ToolsListResult(policy)
		if err != nil {
			return nil, envelope.ErrInternal("tool manifest could not be served: " + err.Error())
		}
		return res, nil
	}
}

// ManifestSource is the registry surface the transport needs. Declared here,
// where it is used, and kept to one method (Go rules: small interfaces, defined
// at the point of use) so the transport does not depend on the whole registry.
type ManifestSource interface {
	ToolsListResult(envelope.CachePolicy) (*envelope.ToolsListResult, error)
}

// The remaining list and read endpoints.
//
// The broker exposes no resources and no prompts in the MVP: schema discovery
// is a tool (warehouse.describe), not a resource tree. The endpoints exist
// anyway and answer with correct, empty, cacheable results — because "this
// server has none" and "this server does not implement the method" are
// different claims, and only one of them is true here. A client that cannot
// tell them apart has to guess.

func ResourcesListHandler(policy envelope.CachePolicy) Handler {
	return func(_ context.Context, _ json.RawMessage) (envelope.Result, *envelope.RPCError) {
		res := &envelope.ResourcesListResult{Resources: []envelope.ResourceDescriptor{}}
		res.SetCache(policy)
		return res, nil
	}
}

func ResourceTemplatesListHandler(policy envelope.CachePolicy) Handler {
	return func(_ context.Context, _ json.RawMessage) (envelope.Result, *envelope.RPCError) {
		res := &envelope.ResourceTemplatesListResult{
			ResourceTemplates: []envelope.ResourceTemplateDescriptor{},
		}
		res.SetCache(policy)
		return res, nil
	}
}

// ResourcesReadHandler. Note the error code: resource-not-found is -32602 in
// this revision, moved from -32002. A server still emitting -32002 is
// non-conformant, and it is one of the violations seeded into the fixture.
func ResourcesReadHandler(policy envelope.CachePolicy) Handler {
	return func(_ context.Context, params json.RawMessage) (envelope.Result, *envelope.RPCError) {
		var p struct {
			URI string `json:"uri"`
		}
		if len(params) > 0 {
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, envelope.ErrInvalidParams("params", err.Error(), "must be an object")
			}
		}
		if p.URI == "" {
			return nil, envelope.ErrInvalidParams("uri", "",
				"is required; try \"warehouse://schema/orders\"")
		}
		return nil, envelope.ErrResourceNotFound(p.URI)
	}
}

func PromptsListHandler(policy envelope.CachePolicy) Handler {
	return func(_ context.Context, _ json.RawMessage) (envelope.Result, *envelope.RPCError) {
		res := &envelope.PromptsListResult{Prompts: []envelope.PromptDescriptor{}}
		res.SetCache(policy)
		return res, nil
	}
}
