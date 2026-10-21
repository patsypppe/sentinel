// Command sentinel-server is the fleet service: it ingests the reports
// `sentinel scan --publish` sends, keeps their history, and serves posture, drift
// and expiring-waiver views over an API and a dashboard.
//
//	sentinel-server serve      run the service (the default)
//	sentinel-server migrate    apply database migrations and exit
//	sentinel-server version
//
// Configuration is environment variables, all prefixed SENTINEL_SERVER_:
//
//	ADDR                    listen address (default 127.0.0.1:8088)
//	INGEST_TOKEN            required. The credential `sentinel scan --publish` presents.
//	READ_TOKEN              optional. When set, the API and dashboard require it.
//	DATABASE_URL            a Postgres URL. Unset, data lives in memory and is lost on restart.
//	MIGRATE_DATABASE_URL    a URL for a role that may create tables; defaults to DATABASE_URL.
//	STALE_AFTER             how old a latest scan may be before a target stops counting as
//	                        passing (default 48h)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/patsypppe/sentinel/fleet/internal/api"
	"github.com/patsypppe/sentinel/fleet/internal/store"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func main() { os.Exit(run(os.Args[1:])) }

func env(key, fallback string) string {
	if v := os.Getenv("SENTINEL_SERVER_" + key); v != "" {
		return v
	}
	return fallback
}

func run(args []string) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "version":
		fmt.Println("sentinel-server", version)
		return 0
	case "migrate":
		return migrate()
	case "serve":
		return serve()
	default:
		fmt.Fprintf(os.Stderr, "sentinel-server: unknown command %q (serve, migrate, version)\n", cmd)
		return 2
	}
}

func migrate() int {
	url := env("MIGRATE_DATABASE_URL", env("DATABASE_URL", ""))
	if url == "" {
		fmt.Fprintln(os.Stderr, "sentinel-server: SENTINEL_SERVER_DATABASE_URL is not set")
		return 2
	}
	applied, err := store.Migrate(context.Background(), url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sentinel-server: migrate:", err)
		return 1
	}
	fmt.Printf("applied %d migration(s) %v\n", len(applied), applied)
	return 0
}

func serve() int {
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ingest := env("INGEST_TOKEN", "")
	if ingest == "" {
		fmt.Fprintln(os.Stderr, "sentinel-server: SENTINEL_SERVER_INGEST_TOKEN is required. "+
			"Without it anyone who can reach this server could publish a clean scan for any target.")
		return 2
	}
	stale, err := time.ParseDuration(env("STALE_AFTER", "48h"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "sentinel-server: SENTINEL_SERVER_STALE_AFTER:", err)
		return 2
	}

	var st store.Store
	if url := env("DATABASE_URL", ""); url != "" {
		if migrateURL := env("MIGRATE_DATABASE_URL", ""); migrateURL != "" {
			applied, err := store.Migrate(ctx, migrateURL)
			if err != nil {
				fmt.Fprintln(os.Stderr, "sentinel-server: migrate:", err)
				return 1
			}
			if len(applied) > 0 {
				log.Info("migrations applied", "versions", applied)
			}
		}
		pg, err := store.OpenPostgres(ctx, url)
		if err != nil {
			// Fail closed: a server that cannot store a scan must not accept one.
			fmt.Fprintln(os.Stderr, "sentinel-server: database:", err)
			return 1
		}
		defer pg.Close()
		st = pg
	} else {
		log.Warn("SENTINEL_SERVER_DATABASE_URL is unset: scans are kept in memory and lost on restart")
		st = store.NewMemory()
	}

	read := env("READ_TOKEN", "")
	if read == "" {
		log.Warn("SENTINEL_SERVER_READ_TOKEN is unset: the API and dashboard are readable by anyone " +
			"who can reach this address. Bind to loopback or put an authenticating proxy in front.")
	}

	handler, err := api.New(api.Config{
		Store: st, IngestToken: ingest, ReadToken: read, StaleAfter: stale, Logger: log,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sentinel-server:", err)
		return 2
	}
	srv := &http.Server{
		Addr:              env("ADDR", "127.0.0.1:8088"),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", srv.Addr, "version", version, "database", env("DATABASE_URL", "") != "")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		fmt.Fprintln(os.Stderr, "sentinel-server:", err)
		return 1
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		return 0
	}
}
