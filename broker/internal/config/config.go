// Package config holds the broker's runtime configuration, read from the
// environment. Every knob SN-PRD-001 §7.4 names lives here, plus the one
// documented MVP addition.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

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

	// Audience validation (SN-CAP-21). Full OAuth is out of scope; the MUST NOT
	// is not.
	OAuthIssuer   string
	OAuthAudience string
	OAuthJWKSPath string

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
	str("BROKER_OTEL_ENDPOINT", &c.OTELEndpoint)

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

	if v, ok := os.LookupEnv("BROKER_ALLOW_LEGACY_UNVERSIONED"); ok {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return c, fmt.Errorf("BROKER_ALLOW_LEGACY_UNVERSIONED: %q is not a boolean: %w", v, err)
		}
		c.AllowLegacyUnversioned = parsed
	}

	return c, c.Validate()
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
