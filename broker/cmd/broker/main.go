// Command broker is the Sentinel MCP server: a single stateless JSON-RPC
// endpoint built natively on the MCP 2026-07-28 specification.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/patsypppe/sentinel/broker/internal/version"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "broker:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: broker <serve|version>")
	}
	switch args[0] {
	case "version":
		_, err := fmt.Fprintf(out, "%s %s (MCP %s)\n",
			version.Name, version.Version, version.ProtocolVersion)
		return err
	case "serve":
		return fmt.Errorf("serve: not implemented until WP-1")
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}
