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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/patsypppe/sentinel/broker/internal/config"
	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/handles"
	"github.com/patsypppe/sentinel/broker/internal/registry"
	"github.com/patsypppe/sentinel/broker/internal/store"
	"github.com/patsypppe/sentinel/broker/internal/tools/warehouse"
	"github.com/patsypppe/sentinel/broker/internal/transport"
	"github.com/patsypppe/sentinel/broker/internal/version"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "broker:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer, in io.Reader) error {
	if len(args) == 0 {
		return errors.New("usage: broker <serve|stdio|manifest|version>")
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
)

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
func buildRegistry(cfg config.Config, st *store.Store) (*registry.Registry, error) {
	if st == nil {
		// `broker manifest` reports the declaration surface, which does not
		// need a database. The manifest is built from schemas and metadata, and
		// none of it depends on a connection.
		return registry.New(
			warehouse.NewDescribeTool(nil),
			warehouse.NewQueryTool(nil, databaselessMinter{}, warehouse.QueryOptions{
				TokenCap: cfg.DefaultTokenCap,
			}),
		)
	}
	pool := st.Pool()
	return registry.New(
		warehouse.NewDescribeTool(pool),
		warehouse.NewQueryTool(pool, handles.NewStore(pool), warehouse.QueryOptions{
			TokenCap:  cfg.DefaultTokenCap,
			HandleTTL: cfg.HandleDefaultTTL,
		}),
	)
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
	reg, err := buildRegistry(cfg, nil)
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

	reg, err := buildRegistry(cfg, st)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	log.Info("tool manifest built",
		"tools", reg.Len(),
		"manifest_hash", reg.ManifestHash(),
		"tokenizer", reg.Tokens().Tokenizer,
		"tokens", reg.Tokens().Manifest)

	srv := transport.NewServer(buildMux(info, reg, cfg), cfg, info, log,
		transport.WithDeprecationRecorder(func(_ context.Context, event, method string) {
			// §8.1 requires the event to be recorded when a request is served
			// through the legacy fallback. WP-8 routes this into the audit log;
			// until then it is at least visible.
			log.Warn("deprecated feature used", "event", event, "method", method)
		}))

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
		log.Info("broker listening",
			"addr", cfg.Addr,
			"protocol", envelope.RevisionCurrent,
			"legacy_fallback", cfg.AllowLegacyUnversioned)
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

	reg, err := buildRegistry(cfg, st)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	s := transport.NewStdio(buildMux(info, reg, cfg), info, envelope.NegotiationConfig{
		Supported:     []string{envelope.RevisionCurrent},
		LegacyVersion: envelope.RevisionLegacy,
		AllowLegacy:   cfg.AllowLegacyUnversioned,
	})
	return s.Serve(context.Background(), in, out)
}
