// Package config holds the broker's runtime configuration, read from the
// environment. Every knob SN-PRD-001 §7.4 names lives here, plus the one
// documented MVP addition.
package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// SealKeySize is the AEAD key length for requestState. It mirrors
// mrtr.KeySize; config does not import mrtr, because a configuration package
// that depends on the thing it configures makes the dependency graph a circle.
const SealKeySize = 32

type Config struct {
	Addr string

	// DatabaseURL is the application role's connection string. It is
	// deliberately not the migration role's: broker_app cannot UPDATE or DELETE
	// the audit table, and a role that could migrate could also drop that
	// REVOKE.
	DatabaseURL        string
	MigrateDatabaseURL string

	// Handles
	HandleDefaultTTL time.Duration

	// MRTR. FlowTTL and ReplayWindow are separate on purpose (docs/PRD.md,
	// recorded divergence): FlowTTL bounds how long a flow may sit AWAITING
	// input, ReplayWindow bounds how long a CONSUMED flow keeps its recorded
	// result for idempotent replay. Collapsing them forces a choice between a
	// short approval window and a long replay guarantee; we want a short window
	// with a long guarantee.
	MRTRFlowTTL      time.Duration
	MRTRReplayWindow time.Duration
	// MRTRSealKey keys the AEAD that seals requestState. 32 bytes.
	MRTRSealKey []byte

	// Cache
	ToolsListCacheTTLMs int

	// Tool response discipline
	DefaultTokenCap int

	// Negotiation
	AllowLegacyUnversioned bool

	// AllowedOrigins is the Origin allowlist the Streamable HTTP transport
	// checks every request against, to close the DNS rebinding attack the
	// specification requires Origin validation for.
	//
	// EMPTY MEANS REJECT EVERY REQUEST THAT CARRIES AN Origin AT ALL, which is
	// the correct default and not a placeholder: this server has no browser
	// clients, so a request carrying an Origin came from a page rather than
	// from an agent, and defaulting to permissive would ship exactly the hole
	// the requirement exists to close. A request with NO Origin header — every
	// non-browser client — is unaffected either way.
	AllowedOrigins []string

	// EmitLegacyErrorCode attaches data.legacyCode to the errors whose codes
	// moved out of -32000…-32019 in this revision, so a client that triaged on
	// the old numbers keeps working for one release. Defaults on.
	//
	// SCHEDULED FOR REMOVAL: this knob and the field it controls exist only for
	// the transition release and go away with it. Nothing may come to depend on
	// data.legacyCode.
	EmitLegacyErrorCode bool

	// Audience validation (SN-CAP-21). Full OAuth is out of scope; the MUST NOT
	// is not.
	OAuthIssuer   string
	OAuthAudience string
	OAuthJWKSPath string
	// OAuthDevSeed derives a deterministic development keypair so the demo can
	// mint tokens with no key files to distribute. Development only: a seed in
	// an environment variable is a private key in an environment variable.
	// OAuthJWKSPath takes precedence when both are set.
	OAuthDevSeed string

	OTELEndpoint string
}

// Default returns the configuration with every value at its documented default.
func Default() Config {
	return Config{
		Addr:                   ":8080",
		HandleDefaultTTL:       15 * time.Minute,
		MRTRFlowTTL:            5 * time.Minute,
		MRTRReplayWindow:       24 * time.Hour,
		ToolsListCacheTTLMs:    300_000,
		DefaultTokenCap:        25_000,
		AllowLegacyUnversioned: true,
		EmitLegacyErrorCode:    true,
		OAuthIssuer:            "https://issuer.sentinel.local",
		OAuthAudience:          "https://broker.sentinel.local",
	}
}

// FromEnv layers environment overrides onto the defaults. Unset variables keep
// their default; a set-but-unparseable variable is an error rather than a
// silent fallback, because a mistyped TTL that silently reverts to the default
// is the kind of bug nobody finds until it matters.
func FromEnv() (Config, error) {
	c := Default()

	str := func(key string, dst *string) {
		if v, ok := os.LookupEnv(key); ok {
			*dst = v
		}
	}
	str("BROKER_ADDR", &c.Addr)
	str("BROKER_DATABASE_URL", &c.DatabaseURL)
	str("BROKER_MIGRATE_DATABASE_URL", &c.MigrateDatabaseURL)
	str("BROKER_OAUTH_ISSUER", &c.OAuthIssuer)
	str("BROKER_OAUTH_AUDIENCE", &c.OAuthAudience)
	str("BROKER_OAUTH_JWKS_PATH", &c.OAuthJWKSPath)
	str("BROKER_OAUTH_DEV_SEED", &c.OAuthDevSeed)
	str("BROKER_OTEL_ENDPOINT", &c.OTELEndpoint)

	// The Origin allowlist. Comma-separated, because an operator setting one
	// origin should not have to learn a syntax for setting two.
	//
	// Note that BROKER_ALLOWED_ORIGINS="" is a set value, not an unset one, and
	// it means the same as leaving it out: allow nothing.
	if v, ok := os.LookupEnv("BROKER_ALLOWED_ORIGINS"); ok {
		c.AllowedOrigins = splitList(v)
	}

	// The AEAD key that seals requestState. Hex-encoded, 32 bytes.
	//
	// An unset key generates an ephemeral one, which is correct for local
	// development and wrong for anything with more than one process or a
	// restart: every in-flight approval becomes unreplayable the moment the key
	// changes. serve() logs a warning when it happens rather than letting it
	// pass silently.
	if v, ok := os.LookupEnv("BROKER_MRTR_SEAL_KEY"); ok {
		key, err := hex.DecodeString(v)
		if err != nil {
			return c, fmt.Errorf("BROKER_MRTR_SEAL_KEY: not valid hex: %w", err)
		}
		if len(key) != SealKeySize {
			return c, fmt.Errorf("BROKER_MRTR_SEAL_KEY: decodes to %d bytes, want %d",
				len(key), SealKeySize)
		}
		c.MRTRSealKey = key
	}

	for _, d := range []struct {
		key string
		dst *time.Duration
	}{
		{"BROKER_HANDLE_DEFAULT_TTL", &c.HandleDefaultTTL},
		{"BROKER_MRTR_FLOW_TTL", &c.MRTRFlowTTL},
		{"BROKER_MRTR_REPLAY_WINDOW", &c.MRTRReplayWindow},
	} {
		if v, ok := os.LookupEnv(d.key); ok {
			parsed, err := time.ParseDuration(v)
			if err != nil {
				return c, fmt.Errorf("%s: %q is not a duration (try \"5m\" or \"24h\"): %w", d.key, v, err)
			}
			*d.dst = parsed
		}
	}

	for _, n := range []struct {
		key string
		dst *int
	}{
		{"BROKER_CACHE_TOOLS_LIST_TTL_MS", &c.ToolsListCacheTTLMs},
		{"BROKER_DEFAULT_TOKEN_CAP", &c.DefaultTokenCap},
	} {
		if v, ok := os.LookupEnv(n.key); ok {
			parsed, err := strconv.Atoi(v)
			if err != nil {
				return c, fmt.Errorf("%s: %q is not an integer: %w", n.key, v, err)
			}
			*n.dst = parsed
		}
	}

	for _, b := range []struct {
		key string
		dst *bool
	}{
		{"BROKER_ALLOW_LEGACY_UNVERSIONED", &c.AllowLegacyUnversioned},
		{"BROKER_EMIT_LEGACY_ERROR_CODE", &c.EmitLegacyErrorCode},
	} {
		if v, ok := os.LookupEnv(b.key); ok {
			parsed, err := strconv.ParseBool(v)
			if err != nil {
				return c, fmt.Errorf("%s: %q is not a boolean: %w", b.key, v, err)
			}
			*b.dst = parsed
		}
	}

	return c, c.Validate()
}

// splitList parses a comma-separated environment value, trimming surrounding
// whitespace and dropping empty entries so `"a, b,"` is the two values it
// visibly is rather than three with one blank. A blank entry in an ALLOWLIST is
// the dangerous kind of typo: it would match the empty Origin.
func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// Validate rejects a configuration that would produce a subtly wrong server
// rather than an obviously broken one.
func (c Config) Validate() error {
	if c.MRTRReplayWindow < c.MRTRFlowTTL {
		return fmt.Errorf(
			"mrtr.replay_window (%s) is shorter than mrtr.flow_ttl (%s): a flow could be "+
				"approved and then have its recorded result age out before the client's first retry, "+
				"which re-opens the exactly-once hole the window exists to close",
			c.MRTRReplayWindow, c.MRTRFlowTTL)
	}
	if c.DefaultTokenCap <= 0 {
		return fmt.Errorf("default token cap must be positive, got %d", c.DefaultTokenCap)
	}
	if c.OAuthAudience == "" {
		return fmt.Errorf("oauth audience must be set: it is the value every inbound token is checked against")
	}
	return nil
}
