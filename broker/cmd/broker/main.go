// Command broker is the Sentinel MCP server: a single stateless JSON-RPC
// endpoint built natively on the MCP 2026-07-28 specification.
//
// There is no session, no handshake and no server-initiated request anywhere in
// this binary. Cross-call state exists only as server-minted, principal-bound
// handles passed as ordinary tool arguments.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/patsypppe/sentinel/broker/internal/audit"
	"github.com/patsypppe/sentinel/broker/internal/authz"
	"github.com/patsypppe/sentinel/broker/internal/config"
	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/handles"
	"github.com/patsypppe/sentinel/broker/internal/mrtr"
	"github.com/patsypppe/sentinel/broker/internal/registry"
	"github.com/patsypppe/sentinel/broker/internal/store"
	"github.com/patsypppe/sentinel/broker/internal/tools/ops"
	"github.com/patsypppe/sentinel/broker/internal/tools/warehouse"
	"github.com/patsypppe/sentinel/broker/internal/transport"
	"github.com/patsypppe/sentinel/broker/internal/version"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "broker:", err)

		// A command may ask for a specific exit code. `audit verify` uses 1 for
		// "a chain failed to verify" and leaves 2 for "the verifier could not
		// run" — a check that cannot tell those apart is not worth running in CI.
		var exit *exitError
		if errors.As(err, &exit) {
			os.Exit(exit.code)
		}
		os.Exit(2)
	}
}

func run(args []string, out io.Writer, in io.Reader) error {
	if len(args) == 0 {
		return errors.New("usage: broker <serve|stdio|manifest|mint-token|audit verify|version>")
	}

	switch args[0] {
	case "version":
		_, err := fmt.Fprintf(out, "%s %s (MCP %s)\n",
			version.Name, version.Version, version.ProtocolVersion)
		return err

	case "serve":
		return serve(out)

	case "manifest":
		return printManifest(out)

	case "mint-token":
		return mintToken(args[1:], out)

	case "audit":
		return auditCommand(args[1:], out)

	case "stdio":
		return serveStdio(in, out)

	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func serverInfo() envelope.Info {
	return envelope.Info{
		Name:    version.Name,
		Version: version.Version,
		Title:   "Sentinel Broker",
	}
}

const (
	// handleSweepInterval is how often expired handles are collected.
	handleSweepInterval = 5 * time.Minute
	// handleRetention keeps expired and revoked rows readable to an audit after
	// they stop resolving. Retention is not revival: they are unresolvable the
	// moment they expire.
	handleRetention = 24 * time.Hour
	// flowSweepInterval is how often abandoned MRTR flows are marked.
	flowSweepInterval = time.Minute
	// partitionRolloverInterval keeps audit partitions ahead of the clock.
	// Hourly is far more often than monthly needs, and costs one no-op query.
	partitionRolloverInterval = time.Hour
)

// demoTenantID is the single tenant the MVP serves. Tenant isolation
// ENFORCEMENT is out of scope (§3.2); the column exists everywhere so adding it
// later is a policy change rather than a migration.
const demoTenantID = "00000000-0000-0000-0000-000000000001"

const instructions = "Stateless MCP broker. Cross-call state is a server-minted handle " +
	"passed as an ordinary tool argument; possession of a handle is not authentication. " +
	"Irreversible tools return resultType=input_required and are completed by retrying " +
	"the original request with inputResponses and the sealed requestState."

// databaselessMinter is used only by `broker manifest`, which reports the
// declaration surface and never executes a tool.
//
// It fails loudly rather than returning a plausible-looking identifier: an
// over-cap result is the one case that needs a handle, and a short answer that
// looks complete is exactly the failure the handle mechanism exists to prevent.
type databaselessMinter struct{}

func (databaselessMinter) Mint(context.Context, registry.Principal, string, json.RawMessage, time.Duration) (string, error) {
	return "", errors.New("no database connection: handles cannot be minted without one")
}

// buildRegistry assembles the tool surface.
//
// Registration is compile-time and the registry validates all six properties of
// every tool, so a tool that has not decided its reversibility, scopes or token
// cap cannot reach this list.
func buildRegistry(cfg config.Config, st *store.Store, engine *mrtr.Engine) (*registry.Registry, error) {
	if st == nil {
		// `broker manifest` reports the declaration surface, which does not
		// need a database. The manifest is built from schemas and metadata, and
		// none of it depends on a connection.
		return registry.New(
			warehouse.NewDescribeTool(nil),
			warehouse.NewQueryTool(nil, databaselessMinter{}, warehouse.QueryOptions{
				TokenCap: cfg.DefaultTokenCap,
			}),
			ops.NewPlanTool(databaselessMinter{}, cfg.HandleDefaultTTL),
			ops.NewApplyTool(nil, nil),
		)
	}
	pool := st.Pool()
	hs := handles.NewStore(pool)
	return registry.New(
		warehouse.NewDescribeTool(pool),
		warehouse.NewQueryTool(pool, hs, warehouse.QueryOptions{
			TokenCap:  cfg.DefaultTokenCap,
			HandleTTL: cfg.HandleDefaultTTL,
		}),
		ops.NewPlanTool(hs, cfg.HandleDefaultTTL),
		ops.NewApplyTool(engine, hs),
	)
}

// buildEngine constructs the MRTR engine, generating an ephemeral seal key if
// none was configured.
func buildEngine(cfg config.Config, st *store.Store, log *slog.Logger) (*mrtr.Engine, error) {
	key := cfg.MRTRSealKey
	if len(key) == 0 {
		generated, err := mrtr.NewKey()
		if err != nil {
			return nil, err
		}
		key = generated
		log.Warn("BROKER_MRTR_SEAL_KEY is unset; generated an ephemeral key. "+
			"Every in-flight approval becomes unreplayable when this process restarts, and "+
			"a second replica cannot unseal this one's requestState",
			"keySize", len(key))
	}

	sealer, err := mrtr.NewSealer(key)
	if err != nil {
		return nil, err
	}
	return mrtr.NewEngine(st.Pool(), sealer, mrtr.Options{
		FlowTTL:      cfg.MRTRFlowTTL,
		ReplayWindow: cfg.MRTRReplayWindow,
	})
}

// buildMux registers every method this server implements. Removed methods are
// deliberately absent from registration and answered by the dispatcher with a
// method-not-found carrying the revision that removed them.
func buildMux(info envelope.Info, reg *registry.Registry, cfg config.Config) *transport.Mux {
	toolsListPolicy := envelope.CachePolicy{
		TTLMs: cfg.ToolsListCacheTTLMs,
		// private, because the visible tool set varies with the principal's
		// scopes. public here would let a shared intermediary serve one
		// tenant's tool list to another.
		Scope: envelope.ScopePrivate,
	}

	mux := transport.NewMux()
	mux.Handle(envelope.MethodDiscover, transport.DiscoverHandler(info, instructions))
	mux.Handle(envelope.MethodToolsList, transport.ToolsListHandler(reg, toolsListPolicy))
	mux.Handle(envelope.MethodToolsCall, transport.ToolsCallHandler(reg))
	mux.Handle(envelope.MethodResourcesList, transport.ResourcesListHandler(toolsListPolicy))
	mux.Handle(envelope.MethodResourceTemplatesList, transport.ResourceTemplatesListHandler(toolsListPolicy))
	mux.Handle(envelope.MethodResourcesRead, transport.ResourcesReadHandler(toolsListPolicy))
	mux.Handle(envelope.MethodPromptsList, transport.PromptsListHandler(toolsListPolicy))
	return mux
}

// manifestReport is what `broker manifest` prints. scripts/measure.py consumes
// it, so it is a stable contract rather than a debug dump.
type manifestReport struct {
	ManifestHash string          `json:"manifestHash"`
	ToolCount    int             `json:"toolCount"`
	Tokenizer    string          `json:"tokenizer"`
	Tokens       int             `json:"tokens"`
	PerTool      map[string]int  `json:"perTool"`
	Manifest     json.RawMessage `json:"manifest"`
}

func printManifest(out io.Writer) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	reg, err := buildRegistry(cfg, nil, nil)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	tokens := reg.Tokens()

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(manifestReport{
		ManifestHash: reg.ManifestHash(),
		ToolCount:    reg.Len(),
		Tokenizer:    tokens.Tokenizer,
		Tokens:       tokens.Manifest,
		PerTool:      tokens.PerTool,
		Manifest:     reg.ManifestBytes(),
	})
}

func serve(out io.Writer) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	log := slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))
	info := serverInfo()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.MigrateDatabaseURL != "" {
		applied, err := store.Migrate(ctx, cfg.MigrateDatabaseURL)
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		if len(applied) > 0 {
			log.Info("migrations applied", "versions", applied)
		}
	}

	var st *store.Store
	if cfg.DatabaseURL != "" {
		st, err = store.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			// Fail closed. A broker that cannot reach its database cannot write
			// an audit row, and an unauditable action does not happen.
			return fmt.Errorf("database: %w", err)
		}
		defer st.Close()
	}

	// The audit sink. §8.7: a failure here fails the invocation, so the broker
	// must be able to write before it accepts traffic.
	var sink *audit.PoolSink
	if st != nil {
		sink = audit.NewPoolSink(st.Pool())
		if err := sink.EnsurePartitions(ctx); err != nil {
			// Fail closed at boot rather than at midnight on the first.
			return fmt.Errorf("audit partitions: %w", err)
		}
		go sink.Writer().RunPartitionRollover(ctx, partitionRolloverInterval, func(err error) {
			if err != nil {
				log.Error("partition rollover failed", "err", err)
			}
		})
	}

	// Sweep expired handles in the background. The grace period keeps recently
	// expired rows readable to an audit for a while: resolution already refuses
	// them, so retention costs nothing and answers "was this handle ever real?"
	// after the fact.
	if st != nil {
		hs := handles.NewStore(st.Pool())
		go hs.RunCollector(ctx, handleSweepInterval, handleRetention, func(n int64, err error) {
			switch {
			case err != nil:
				log.Error("handle sweep failed", "err", err)
			case n > 0:
				log.Info("handles collected", "count", n)
			}
		})
	}

	engine, err := buildEngine(cfg, st, log)
	if err != nil {
		return fmt.Errorf("mrtr: %w", err)
	}
	go sweepFlows(ctx, engine, log)

	reg, err := buildRegistry(cfg, st, engine)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	log.Info("tool manifest built",
		"tools", reg.Len(),
		"manifest_hash", reg.ManifestHash(),
		"tokenizer", reg.Tokens().Tokenizer,
		"tokens", reg.Tokens().Manifest)

	auth, err := buildAuthenticator(cfg, log)
	if err != nil {
		return fmt.Errorf("authz: %w", err)
	}

	opts := []transport.Option{
		transport.WithAuthenticator(auth),
		transport.WithLegacyErrorCodes(cfg.EmitLegacyErrorCode),
		transport.WithDeprecationRecorder(func(_ context.Context, event, method string) {
			// §8.1 requires the event to be recorded when a request is served
			// through the legacy fallback. WP-8 routes this into the audit log;
			// until then it is at least visible.
			log.Warn("deprecated feature used", "event", event, "method", method)
		}),
	}

	// Guarded rather than passed unconditionally: a nil *audit.PoolSink placed
	// in an AuditSink interface is a NON-NIL interface holding a nil pointer,
	// so `s.audit != nil` would be true and the first invocation would panic
	// instead of skipping the write.
	if sink != nil {
		opts = append(opts, transport.WithAuditSink(sink))
	}

	srv := transport.NewServer(buildMux(info, reg, cfg), cfg, info, log, opts...)

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		// allowed_origins is logged because its default — reject every request
		// that carries an Origin at all — is a REFUSAL, and an operator
		// debugging a browser client that gets 403 should find the reason in
		// the first line of the log rather than in the source.
		log.Info("broker listening",
			"addr", cfg.Addr,
			"protocol", envelope.RevisionCurrent,
			"legacy_fallback", cfg.AllowLegacyUnversioned,
			"allowed_origins", cfg.AllowedOrigins)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

// auditCommand implements `broker audit verify --from --to`.
//
// It walks each tenant's chain and reports the FIRST break. First, not all:
// after a rewritten row every subsequent link fails too, and printing a
// thousand breaks buries the one that matters.
//
// The exit code is the contract: 0 when every chain verifies, 1 when any does
// not, and 2 when the check itself could not run. A verifier that cannot
// distinguish "the log is intact" from "I could not read the log" is not worth
// running in CI.
func auditCommand(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New("usage: broker audit verify --from YYYY-MM-DD --to YYYY-MM-DD [--tenant ID]")
	}

	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(out)
	from := fs.String("from", "", "start of the window, YYYY-MM-DD (required)")
	to := fs.String("to", "", "end of the window, exclusive, YYYY-MM-DD (required)")
	tenantID := fs.String("tenant", "", "a single tenant; default is every tenant with rows in the window")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *from == "" || *to == "" {
		fs.Usage()
		return errors.New("audit verify: --from and --to are both required")
	}

	fromAt, err := time.Parse("2006-01-02", *from)
	if err != nil {
		return fmt.Errorf("--from %q is not YYYY-MM-DD; try 2026-09-01: %w", *from, err)
	}
	toAt, err := time.Parse("2006-01-02", *to)
	if err != nil {
		return fmt.Errorf("--to %q is not YYYY-MM-DD; try 2026-09-30: %w", *to, err)
	}

	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer st.Close()

	verifier := audit.NewVerifier(st.Pool())

	tenants := []string{*tenantID}
	if *tenantID == "" {
		tenants, err = verifier.Tenants(ctx, fromAt, toAt)
		if err != nil {
			return err
		}
	}
	if len(tenants) == 0 {
		_, err := fmt.Fprintf(out, "no audit rows between %s and %s\n", *from, *to)
		return err
	}

	broken := 0
	for _, id := range tenants {
		res, err := verifier.Verify(ctx, id, fromAt, toAt)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, res.String()); err != nil {
			return err
		}
		if !res.OK() {
			broken++
		}
	}

	if broken > 0 {
		return &exitError{code: 1, msg: fmt.Sprintf("%d of %d chain(s) failed to verify", broken, len(tenants))}
	}
	return nil
}

// exitError carries a specific exit code, so a failed verification is
// distinguishable from a verifier that could not run.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// mintToken issues a development token from the configured seed.
//
// The audience is a flag with no default, deliberately. To DEMONSTRATE the
// specification's MUST NOT you have to be able to mint a token for the wrong
// audience as easily as for the right one, and watch this server refuse it:
//
//	broker mint-token --audience https://billing.sentinel.local  →  refused
//	broker mint-token --audience https://broker.sentinel.local   →  accepted
func mintToken(args []string, out io.Writer) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if cfg.OAuthDevSeed == "" {
		return errors.New("mint-token needs BROKER_OAUTH_DEV_SEED; it mints development " +
			"tokens only and cannot sign with a production JWKS")
	}

	fs := flag.NewFlagSet("mint-token", flag.ContinueOnError)
	fs.SetOutput(out)
	principal := fs.String("principal", "", "principal id to embed (required)")
	subject := fs.String("subject", "dev@sentinel.local", "token subject")
	audience := fs.String("audience", "", "audience to mint for (required; use a wrong one to see it refused)")
	scopes := fs.String("scopes", "", "space-delimited scopes")
	ttl := fs.Duration("ttl", time.Hour, "token lifetime")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *principal == "" || *audience == "" {
		fs.Usage()
		return errors.New("mint-token: --principal and --audience are both required")
	}

	pair, err := authz.DeriveDevKey(cfg.OAuthDevSeed)
	if err != nil {
		return err
	}
	token, err := pair.Mint(authz.MintRequest{
		Issuer:      cfg.OAuthIssuer,
		Audience:    *audience,
		Subject:     *subject,
		PrincipalID: *principal,
		Scopes:      *scopes,
		TTL:         *ttl,
	}, time.Now())
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(out, token)
	return err
}

// buildAuthenticator chooses the token validator or, only when explicitly
// asked, the local development stand-in.
//
// A server with neither configured gets a DevAuthenticator that is DISABLED,
// which refuses every authenticated request. That is the correct failure mode:
// an authentication layer nobody configured must not serve anonymously.
func buildAuthenticator(cfg config.Config, log *slog.Logger) (transport.Authenticator, error) {
	if cfg.OAuthJWKSPath != "" {
		keys, err := authz.LoadKeySet(cfg.OAuthJWKSPath)
		if err != nil {
			return nil, err
		}
		log.Info("token validation enabled",
			"issuer", cfg.OAuthIssuer, "audience", cfg.OAuthAudience, "jwks", cfg.OAuthJWKSPath)
		return authz.NewTokenAuthenticator(authz.Config{
			Issuer:   cfg.OAuthIssuer,
			Audience: cfg.OAuthAudience,
			Keys:     keys,
			// Small on purpose: leeway is for clock skew, not for staleness. A
			// generous value is an expired token that still works.
			Leeway:   30 * time.Second,
			TenantID: demoTenantID,
		}), nil
	}

	if cfg.OAuthDevSeed != "" {
		pair, err := authz.DeriveDevKey(cfg.OAuthDevSeed)
		if err != nil {
			return nil, err
		}
		keys, err := pair.KeySet()
		if err != nil {
			return nil, err
		}
		log.Warn("token validation enabled with a SEED-DERIVED development key. "+
			"Tokens are validated for real — signature, issuer, audience and expiry — but the "+
			"signing key is derived from BROKER_OAUTH_DEV_SEED and is not a secret. "+
			"Use BROKER_OAUTH_JWKS_PATH in production",
			"issuer", cfg.OAuthIssuer, "audience", cfg.OAuthAudience, "kid", authz.DevKeyID)
		return authz.NewTokenAuthenticator(authz.Config{
			Issuer:   cfg.OAuthIssuer,
			Audience: cfg.OAuthAudience,
			Keys:     keys,
			Leeway:   30 * time.Second,
			TenantID: demoTenantID,
		}), nil
	}

	dev := transport.DevAuthenticator{
		Enabled: os.Getenv("BROKER_DEV_AUTH") == "1",
		Tenant:  demoTenantID,
	}
	switch {
	case dev.Enabled:
		log.Warn("BROKER_DEV_AUTH=1: principals are read from request headers and NO TOKEN " +
			"IS VALIDATED. Local development only; set BROKER_OAUTH_JWKS_PATH for real " +
			"audience validation")
	default:
		log.Warn("no authentication is configured: every authenticated method will be " +
			"refused. Set BROKER_OAUTH_JWKS_PATH, or BROKER_DEV_AUTH=1 for local development")
	}
	return dev, nil
}

// sweepFlows marks flows that were opened, never retried and have aged out. A
// flow left awaiting input forever is harmless, but marking it makes "how many
// approvals were abandoned?" an answerable question.
func sweepFlows(ctx context.Context, engine *mrtr.Engine, log *slog.Logger) {
	ticker := time.NewTicker(flowSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := engine.Sweep(ctx)
			switch {
			case err != nil:
				log.Error("flow sweep failed", "err", err)
			case n > 0:
				log.Info("flows marked expired", "count", n)
			}
		}
	}
}

func serveStdio(in io.Reader, out io.Writer) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	info := serverInfo()

	var st *store.Store
	if cfg.DatabaseURL != "" {
		st, err = store.Open(context.Background(), cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("database: %w", err)
		}
		defer st.Close()
	}

	var engine *mrtr.Engine
	if st != nil {
		engine, err = buildEngine(cfg, st, slog.Default())
		if err != nil {
			return fmt.Errorf("mrtr: %w", err)
		}
	}

	reg, err := buildRegistry(cfg, st, engine)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	s := transport.NewStdio(buildMux(info, reg, cfg), info, envelope.NegotiationConfig{
		Supported:     []string{envelope.RevisionCurrent},
		LegacyVersion: envelope.RevisionLegacy,
		AllowLegacy:   cfg.AllowLegacyUnversioned,
	}, transport.WithStdioLegacyErrorCodes(cfg.EmitLegacyErrorCode))
	return s.Serve(context.Background(), in, out)
}
