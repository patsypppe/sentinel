// Command example serves the minimal MCP server on :8080 (or $PORT, or -addr).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/patsypppe/sentinel/mcp/example"
)

func main() {
	os.Exit(run())
}

// run is separate from main so its deferred cleanup always runs: os.Exit skips
// defers, and the signal handler should be released before the process ends.
func run() int {
	addr := flag.String("addr", ":"+envOr("PORT", "8080"), "address to listen on")
	flag.Parse()

	srv, err := example.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "example:", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "serving %s\n", example.Describe(srv))
	if err := srv.ListenAndServe(ctx, *addr); err != nil {
		fmt.Fprintln(os.Stderr, "example:", err)
		return 1
	}
	return 0
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
