package server

import (
	"io"
	"net/http"
	"os"

	"github.com/patsypppe/sentinel/mcp/envelope"
	"github.com/patsypppe/sentinel/mcp/registry"
	"github.com/patsypppe/sentinel/mcp/transport"
)

func logOutput() io.Writer { return os.Stderr }

type anonymous struct{ principal registry.Principal }

func (a anonymous) Authenticate(*http.Request) (registry.Principal, *envelope.RPCError) {
	return a.principal, nil
}

// InsecureAnonymous authenticates every request as the given principal, without
// looking at it.
//
// It is for local development, tests and the example. The name is the warning: a
// server using it will serve anyone who can reach it with every scope it lists. For
// real traffic, use the audience-validating authenticator in the authz package,
// which accepts only a token issued for this server and forwards none.
func InsecureAnonymous(p registry.Principal) transport.Authenticator {
	return anonymous{principal: p}
}
