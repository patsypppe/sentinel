// Package version carries the broker's build identity. It is echoed to clients
// as `io.modelcontextprotocol/serverInfo` on every result, so it is a protocol
// surface, not just a build detail.
package version

// Version is the broker's semantic version. Overridden at build time with
// -ldflags "-X github.com/patsypppe/sentinel/broker/internal/version.Version=..."
var Version = "0.1.0-dev"

// Name is the server identity reported in serverInfo. Stable across releases;
// clients key cache entries on the (name, version) pair.
const Name = "sentinel-broker"

// ProtocolVersion is the MCP revision this server implements natively.
const ProtocolVersion = "2026-07-28"
