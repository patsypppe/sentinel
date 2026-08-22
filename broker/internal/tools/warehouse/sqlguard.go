// Package warehouse implements the MVP tool domain: warehouse.describe and
// warehouse.query.
//
// warehouse.query is chosen carefully (docs/HANDOFF.md §9.3): it produces
// variably-sized output, which forces handles; it has real permissions, which
// forces scopes; and it is read-only, which keeps MRTR off the MVP critical
// path until ops.deployment_apply arrives.
package warehouse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The SQL guard. §9.3, stated plainly: "the principal's scopes map to an
// allowlist of schemas and tables; queries are parsed and rejected if they
// touch anything outside it; a statement timeout and a row cap are enforced
// server-side. Do not attempt to make arbitrary SQL safe by string inspection —
// allowlist, parse, cap."
//
// The parser used here is POSTGRES ITSELF. `EXPLAIN (FORMAT JSON)` plans the
// statement without executing it and reports every relation the plan will
// touch. That beats a third-party SQL parser on the one axis that matters for
// a security control: it cannot disagree with what actually executes. A vendored
// parser and the server can drift — over a new syntax, a search_path subtlety,
// a view that expands to something else — and every such disagreement is a
// bypass. Asking the executor what it is about to read has no such gap.
//
// Three layers, in order:
//
//  1. READ-ONLY TRANSACTION. Postgres itself rejects any write, so DML and DDL
//     never reach the allowlist check at all.
//  2. EXPLAIN + allowlist. Every relation in the plan must be in the set the
//     principal's scopes permit, including relations reached through views and
//     subqueries, which is exactly what string inspection cannot see.
//  3. STATEMENT TIMEOUT AND ROW CAP, applied server-side inside that same
//     transaction.

// Grant is a schema/table pair a scope permits.
type Grant struct {
	Schema string
	Table  string
}

func (g Grant) String() string { return g.Schema + "." + g.Table }

// Allowlist is the set of relations a principal may read.
type Allowlist struct {
	grants map[string]bool
	sorted []string
}

// NewAllowlist builds the set. An empty allowlist permits nothing, which is the
// correct default for a principal holding no warehouse scopes.
func NewAllowlist(grants ...Grant) Allowlist {
	a := Allowlist{grants: make(map[string]bool, len(grants))}
	for _, g := range grants {
		a.grants[g.String()] = true
		a.sorted = append(a.sorted, g.String())
	}
	sort.Strings(a.sorted)
	return a
}

// Permits reports exact membership of a schema-qualified relation.
func (a Allowlist) Permits(schema, table string) bool {
	return a.grants[schema+"."+table]
}

// Relations lists what is permitted, in a stable order, for error messages.
func (a Allowlist) Relations() []string { return a.sorted }

// ScopeGrants maps each scope to the relations it confers. Scope names are
// matched exactly; there is no prefix or wildcard rule, because a wildcard is
// how an allowlist quietly stops being one.
var ScopeGrants = map[string][]Grant{
	"warehouse:read": {
		{Schema: "warehouse", Table: "customers"},
		{Schema: "warehouse", Table: "orders"},
	},
}

// AllowlistFor derives the relations a set of scopes permits.
func AllowlistFor(scopes []string) Allowlist {
	var grants []Grant
	for _, s := range scopes {
		grants = append(grants, ScopeGrants[s]...)
	}
	return NewAllowlist(grants...)
}

// GuardConfig bounds an execution.
type GuardConfig struct {
	Allowlist        Allowlist
	StatementTimeout time.Duration
	RowCap           int
}

// ErrRelationDenied names the relation and what would have worked. §8.4:
// "invalid argument" is a bug; an error a model can act on is the standard.
type ErrRelationDenied struct {
	Relation  string
	Permitted []string
}

func (e *ErrRelationDenied) Error() string {
	return fmt.Sprintf(
		"query touches %q, which your scopes do not permit; readable relations are: %s",
		e.Relation, strings.Join(e.Permitted, ", "))
}

// DeniedByGrant reports whether a Postgres error is an insufficient-privilege
// refusal (SQLSTATE 42501).
//
// The database grant is defence in depth BEHIND the scope allowlist: broker_app
// holds SELECT on exactly the relations some scope can confer, and nothing else.
// For a relation no scope confers, Postgres refuses at EXPLAIN time and the
// allowlist never gets to speak — the backstop works, but its error is a bare
// "permission denied for schema ...", which tells a caller nothing about what
// they could have read instead.
//
// Translating it means the caller gets the same actionable answer either way,
// while the grant remains the layer that actually holds if the allowlist is ever
// wrong. The layers stay distinct; only the message is unified.
func DeniedByGrant(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501"
}

// ErrNotReadOnly is returned when the statement is not a read.
type ErrNotReadOnly struct{ Detail string }

func (e *ErrNotReadOnly) Error() string {
	return "warehouse.query executes read-only statements; use a SELECT (" + e.Detail + ")"
}

// planNode is the shape of one node of EXPLAIN (FORMAT JSON) output that this
// guard cares about. Decoded into named fields rather than map[string]any so
// nothing is coerced on the way in.
type planNode struct {
	RelationName string     `json:"Relation Name"`
	Schema       string     `json:"Schema"`
	Plans        []planNode `json:"Plans"`
	// A CTE or subplan may carry its own scan nodes; Plans covers them.
}

type explainOutput struct {
	Plan planNode `json:"Plan"`
}

// Relations walks a plan and returns every schema-qualified relation it reads.
func (p planNode) Relations(into map[string]bool) {
	if p.RelationName != "" {
		schema := p.Schema
		if schema == "" {
			// A plan node without a schema means the relation resolved through
			// search_path. The guard sets an explicit, empty search_path before
			// planning precisely so this cannot happen silently; treat it as
			// unknown rather than assuming a schema on the query's behalf.
			schema = "?"
		}
		into[schema+"."+p.RelationName] = true
	}
	for _, child := range p.Plans {
		child.Relations(into)
	}
}

// PlanRelations asks Postgres which relations a statement will read, without
// executing it.
func PlanRelations(ctx context.Context, tx pgx.Tx, sql string) ([]string, error) {
	var raw []byte
	// VERBOSE is load-bearing, not decoration. Plain `EXPLAIN (FORMAT JSON)`
	// emits "Relation Name" but NOT "Schema", so every relation would arrive
	// unqualified and the guard could not tell warehouse.orders from any other
	// schema's orders. VERBOSE adds the "Schema" field, which is the whole
	// input to the allowlist check.
	//
	// The statement is interpolated into EXPLAIN rather than bound as a
	// parameter because EXPLAIN takes a statement, not a value. It runs inside
	// a read-only transaction with an empty search_path, and it is only ever
	// PLANNED here — execution happens separately, after this returns clean.
	if err := tx.QueryRow(ctx, "EXPLAIN (FORMAT JSON, VERBOSE) "+sql).Scan(&raw); err != nil {
		return nil, err
	}

	var plans []explainOutput
	if err := json.Unmarshal(raw, &plans); err != nil {
		return nil, fmt.Errorf("warehouse: decode plan: %w", err)
	}

	found := map[string]bool{}
	for _, p := range plans {
		p.Plan.Relations(found)
	}

	out := make([]string, 0, len(found))
	for r := range found {
		out = append(out, r)
	}
	sort.Strings(out)
	return out, nil
}

// CheckAllowlist verifies every planned relation against the allowlist.
func CheckAllowlist(relations []string, allow Allowlist) error {
	for _, r := range relations {
		schema, table, ok := strings.Cut(r, ".")
		if !ok || !allow.Permits(schema, table) {
			return &ErrRelationDenied{Relation: r, Permitted: allow.Relations()}
		}
	}
	return nil
}
