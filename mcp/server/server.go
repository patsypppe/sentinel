// Package server wires the default MCP 2026-07-28 pipeline in one call.
//
// A kit whose smallest working example is two hundred lines of wiring is a kit
// nobody adopts. `New` builds the registry, the method table, the header contract,
// the authenticator seam and the audit seam, and hands back something with a
// Handler and a ListenAndServe. Everything it builds is a package of this module
// you can use directly if you need to deviate.
//
// Two defaults are decisions, not conveniences:
//
//   - There is no default authenticator. A server that does not say how it
//     identifies callers is refused at construction, because an authentication
//     layer that was never configured must fail closed. For local development,
//     InsecureAnonymous says so in its name.
//   - There is a default audit sink, in memory. The rule is that every invocation
//     is audited and a failed write fails the call, so "no sink" would make the rule
//     opt-in. Replace it with durable storage before you serve real traffic.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/patsypppe/sentinel/mcp/audit"
	"github.com/patsypppe/sentinel/mcp/envelope"
	"github.com/patsypppe/sentinel/mcp/registry"
	"github.com/patsypppe/sentinel/mcp/transport"
)

// Options configures New.
type Options struct {
	// Info is echoed to clients as serverInfo on every result. Name is required.
	Info envelope.Info
	// Instructions is shown to clients in server/discover. Optional.
	Instructions string
	// Tools is the tool surface. Each must declare all six properties of the Tool
	// contract; the registry refuses one that has not.
	Tools []registry.Tool
	// Authenticator identifies the caller on every request. Required.
	Authenticator transport.Authenticator
	// AuditSink records every invocation. Defaults to an in-memory sink.
	AuditSink transport.AuditSink
	// Logger defaults to a JSON logger on stderr at info level.
	Logger *slog.Logger
	// AllowedOrigins is the Origin allowlist. Empty rejects every request that
	// carries an Origin, which is the correct default for a server with no
	// browser clients.
	AllowedOrigins []string
	// SpanRecorder, when set, receives a span for every dispatched request. Pass an
	// otlp.Exporter's Record to export traces. It must not block.
	SpanRecorder func(transport.Span)
	// ToolsListCacheTTLMs is how long a client may cache tools/list. Zero means
	// five minutes.
	ToolsListCacheTTLMs int
}

// Server is a configured, not yet listening, MCP server.
type Server struct {
	http     *transport.Server
	registry *registry.Registry
	memory   *audit.MemorySink
	logger   *slog.Logger
}

// New validates the options and builds the server.
func New(o Options) (*Server, error) {
	if o.Info.Name == "" {
		return nil, errors.New("server: Options.Info.Name is required; it is echoed as serverInfo on every result")
	}
	if o.Authenticator == nil {
		return nil, errors.New(
			"server: Options.Authenticator is required. A server that has not said how it " +
				"identifies callers would have to serve everyone or no one; for local " +
				"development use server.InsecureAnonymous")
	}
	reg, err := registry.New(o.Tools...)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}

	logger := o.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(logOutput(), &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	ttl := o.ToolsListCacheTTLMs
	if ttl == 0 {
		ttl = 300_000
	}
	policy := envelope.CachePolicy{
		TTLMs: ttl,
		// private: the visible tool set can vary with the caller's scopes, and
		// public would let a shared intermediary serve one caller's list to another.
		Scope: envelope.ScopePrivate,
	}

	s := &Server{registry: reg, logger: logger}
	sink := o.AuditSink
	if sink == nil {
		s.memory = audit.NewMemorySink(0)
		sink = s.memory
	}
	opts := []transport.Option{
		transport.WithAuthenticator(o.Authenticator),
		transport.WithAuditSink(sink),
	}
	if o.SpanRecorder != nil {
		opts = append(opts, transport.WithSpanRecorder(o.SpanRecorder))
	}
	s.http = transport.NewServer(
		DefaultMux(o.Info, o.Instructions, reg, policy),
		transport.Settings{AllowedOrigins: o.AllowedOrigins},
		o.Info,
		logger,
		opts...,
	)
	return s, nil
}

// DefaultMux registers every method a server of this revision implements.
//
// Removed methods are deliberately absent: the dispatcher answers them with
// method-not-found carrying the revision that removed them, which is what a
// migrating client needs to be told.
func DefaultMux(
	info envelope.Info,
	instructions string,
	reg *registry.Registry,
	policy envelope.CachePolicy,
) *transport.Mux {
	mux := transport.NewMux()
	mux.Handle(envelope.MethodDiscover, transport.DiscoverHandler(info, instructions))
	mux.Handle(envelope.MethodToolsList, transport.ToolsListHandler(reg, policy))
	mux.Handle(envelope.MethodToolsCall, transport.ToolsCallHandler(reg))
	mux.Handle(envelope.MethodResourcesList, transport.ResourcesListHandler(policy))
	mux.Handle(envelope.MethodResourceTemplatesList, transport.ResourceTemplatesListHandler(policy))
	mux.Handle(envelope.MethodResourcesRead, transport.ResourcesReadHandler(policy))
	mux.Handle(envelope.MethodPromptsList, transport.PromptsListHandler(policy))
	return mux
}

// Handler is the HTTP handler: POST /mcp, and GET /healthz.
func (s *Server) Handler() http.Handler { return s.http.Routes() }

// Registry is the tool registry, for inspecting the manifest hash and token cost.
func (s *Server) Registry() *registry.Registry { return s.registry }

// Audit returns the default in-memory sink, or nil if you supplied your own.
func (s *Server) Audit() *audit.MemorySink { return s.memory }

// ListenAndServe serves on addr until ctx is cancelled, then shuts down gracefully.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("listening", "addr", addr, "protocol", envelope.RevisionCurrent,
			"tools", s.registry.Len(), "manifest_hash", s.registry.ManifestHash())
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdown)
	}
}
