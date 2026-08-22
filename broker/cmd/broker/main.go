// Command broker is the Sentinel MCP server: a single stateless JSON-RPC
// endpoint built natively on the MCP 2026-07-28 specification.
//
// There is no session, no handshake and no server-initiated request anywhere in
// this binary. Cross-call state exists only as server-minted, principal-bound
// handles passed as ordinary tool arguments.
package main

import (
	"context"
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
		return errors.New("usage: broker <serve|stdio|version>")
	}

	switch args[0] {
	case "version":
		_, err := fmt.Fprintf(out, "%s %s (MCP %s)\n",
			version.Name, version.Version, version.ProtocolVersion)
		return err

	case "serve":
		return serve(out)

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

const instructions = "Stateless MCP broker. Cross-call state is a server-minted handle " +
	"passed as an ordinary tool argument; possession of a handle is not authentication. " +
	"Irreversible tools return resultType=input_required and are completed by retrying " +
	"the original request with inputResponses and the sealed requestState."

// buildMux registers every method this server implements. Removed methods are
// deliberately absent from registration and answered by the dispatcher with a
// method-not-found carrying the revision that removed them.
func buildMux(info envelope.Info) *transport.Mux {
	mux := transport.NewMux()
	mux.Handle(envelope.MethodDiscover, transport.DiscoverHandler(info, instructions))
	return mux
}

func serve(out io.Writer) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	log := slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))
	info := serverInfo()

	srv := transport.NewServer(buildMux(info), cfg, info, log,
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
	s := transport.NewStdio(buildMux(info), info, envelope.NegotiationConfig{
		Supported:     []string{envelope.RevisionCurrent},
		LegacyVersion: envelope.RevisionLegacy,
		AllowLegacy:   cfg.AllowLegacyUnversioned,
	})
	return s.Serve(context.Background(), in, out)
}
