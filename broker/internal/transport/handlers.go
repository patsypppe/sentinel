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
