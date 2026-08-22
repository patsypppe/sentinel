package warehouse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/registry"
)

// Minter mints a server-minted, principal-bound state handle.
//
// Declared here, where it is consumed, and kept to one method. The
// implementation lands in WP-5; what matters at this layer is that an
// over-cap result becomes a handle rather than a silent truncation.
type Minter interface {
	Mint(ctx context.Context, p registry.Principal, kind string, payload json.RawMessage, ttl time.Duration) (string, error)
}

const (
	// HandleKindQueryResult labels a handle holding a full result set.
	HandleKindQueryResult = "query_result"
	// defaultRowCap bounds a single result before the handle path takes over.
	defaultRowCap = 1000
	// inlineSampleRows is how much of an over-cap result is inlined alongside
	// the handle. Enough for a model to see the shape and decide whether the
	// full result is worth fetching.
	inlineSampleRows = 20
)

// QueryTool is warehouse.query.
type QueryTool struct {
	pool             *pgxpool.Pool
	minter           Minter
	tokenCap         int
	rowCap           int
	statementTimeout time.Duration
	handleTTL        time.Duration
}

// QueryOptions configures the tool.
type QueryOptions struct {
	TokenCap         int
	RowCap           int
	StatementTimeout time.Duration
	HandleTTL        time.Duration
}

func NewQueryTool(pool *pgxpool.Pool, minter Minter, opts QueryOptions) *QueryTool {
	if opts.TokenCap <= 0 {
		opts.TokenCap = 25_000
	}
	if opts.RowCap <= 0 {
		opts.RowCap = defaultRowCap
	}
	if opts.StatementTimeout <= 0 {
		opts.StatementTimeout = 5 * time.Second
	}
	if opts.HandleTTL <= 0 {
		opts.HandleTTL = 15 * time.Minute
	}
	return &QueryTool{
		pool:             pool,
		minter:           minter,
		tokenCap:         opts.TokenCap,
		rowCap:           opts.RowCap,
		statementTimeout: opts.StatementTimeout,
		handleTTL:        opts.HandleTTL,
	}
}

func (t *QueryTool) Name() string { return "warehouse.query" }

func (t *QueryTool) Description() string {
	return "Run a read-only SQL query against the warehouse. Table names must be " +
		"schema-qualified (for example warehouse.orders); the search path is empty. " +
		"Only relations your scopes permit are readable, and the query is planned " +
		"before it runs so a denial names the relation. Results larger than the token " +
		"cap return a handle plus a summary rather than being truncated."
}

func (t *QueryTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
      "type": "object",
      "properties": {
        "sql": {
          "type": "string",
          "description": "A single read-only SELECT. Schema-qualify every table, e.g. warehouse.orders."
        },
        "response_format": {
          "type": "string",
          "enum": ["concise", "detailed"],
          "default": "concise",
          "description": "concise names each column once; detailed repeats every key on every row."
        },
        "max_rows": {
          "type": "integer",
          "minimum": 1,
          "description": "Row ceiling for this call. Capped by the server's own limit."
        }
      },
      "required": ["sql"],
      "additionalProperties": false
    }`)
}

func (t *QueryTool) OutputSchema() json.RawMessage {
	return json.RawMessage(`{
      "type": "object",
      "properties": {
        "columns": {"type": "array", "items": {"type": "string"}},
        "rows": {"type": "array"},
        "rowCount": {"type": "integer"},
        "truncated": {"type": "boolean"},
        "handle": {"type": "string", "description": "Present when the full result exceeded the token cap."}
      },
      "required": ["rowCount"]
    }`)
}

func (t *QueryTool) Scopes() []string { return []string{"warehouse:read"} }

// Reversibility is Reversible: warehouse.query is read-only, which is precisely
// why it keeps MRTR off the MVP critical path.
func (t *QueryTool) Reversibility() registry.Reversibility { return registry.Reversible }

// CachePolicy is private with a short TTL. The rows a principal can read depend
// on that principal's scopes, so a shared intermediary must never reuse them.
func (t *QueryTool) CachePolicy() envelope.CachePolicy {
	return envelope.CachePolicy{TTLMs: 30_000, Scope: envelope.ScopePrivate}
}

func (t *QueryTool) TokenCap() int { return t.tokenCap }

type queryArgs struct {
	SQL            string `json:"sql"`
	ResponseFormat string `json:"response_format"`
	MaxRows        int    `json:"max_rows"`
}

// Call plans, checks, executes and formats. The three guard layers of
// sqlguard.go apply in order, all inside one read-only transaction.
func (t *QueryTool) Call(ctx context.Context, p registry.Principal, raw json.RawMessage) (registry.Result, error) {
	var args queryArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, fmt.Errorf("%q could not be parsed as an object: %w; "+
				"try {\"sql\": \"SELECT 1\"}", "arguments", err)
		}
	}
	if args.SQL == "" {
		return nil, errors.New("\"sql\" is required; try " +
			"{\"sql\": \"SELECT order_id, status FROM warehouse.orders LIMIT 10\"}")
	}

	format, err := ParseResponseFormat(args.ResponseFormat)
	if err != nil {
		return nil, err
	}

	rowCap := t.rowCap
	if args.MaxRows > 0 && args.MaxRows < rowCap {
		rowCap = args.MaxRows
	}

	allow := AllowlistFor(p.Scopes)
	if len(allow.Relations()) == 0 {
		return nil, fmt.Errorf(
			"your scopes %v grant no readable relations; warehouse.query needs \"warehouse:read\"",
			p.Scopes)
	}

	rows, truncated, err := t.execute(ctx, args.SQL, allow, rowCap)
	if err != nil {
		return nil, err
	}

	return t.respond(ctx, p, rows, truncated, format, rowCap)
}

// execute runs the three guard layers in one read-only transaction.
func (t *QueryTool) execute(ctx context.Context, sql string, allow Allowlist, rowCap int) (Rows, bool, error) {
	// Layer 1: a read-only transaction. Postgres rejects any write itself, so
	// DML and DDL never reach the allowlist check at all.
	tx, err := t.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return Rows{}, false, fmt.Errorf("warehouse: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Layer 3a: the statement timeout, set before anything is planned so a
	// pathological plan cannot outlive it either.
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = '%dms'",
		t.statementTimeout.Milliseconds())); err != nil {
		return Rows{}, false, fmt.Errorf("warehouse: set statement_timeout: %w", err)
	}

	// An empty search_path forces every table name to be schema-qualified. That
	// removes the case where a plan node reports a relation with no schema and
	// the guard would have to guess which one was meant.
	if _, err := tx.Exec(ctx, "SET LOCAL search_path = ''"); err != nil {
		return Rows{}, false, fmt.Errorf("warehouse: set search_path: %w", err)
	}

	// Layer 2: plan the statement without executing it, then check every
	// relation the plan will touch — including those reached through views and
	// subqueries, which is exactly what string inspection cannot see.
	relations, err := PlanRelations(ctx, tx, sql)
	if err != nil {
		if DeniedByGrant(err) {
			// The database grant refused before the allowlist could. Same
			// answer, phrased the way the allowlist would have phrased it.
			return Rows{}, false, &ErrRelationDenied{
				Relation:  "a relation outside your scopes",
				Permitted: allow.Relations(),
			}
		}
		return Rows{}, false, planError(err)
	}
	if err := CheckAllowlist(relations, allow); err != nil {
		return Rows{}, false, err
	}

	// Layer 3b: the row cap. One extra row is fetched so truncation is detected
	// rather than inferred.
	capped := fmt.Sprintf("SELECT * FROM (%s) AS sentinel_scoped LIMIT %d", sql, rowCap+1)

	pgRows, err := tx.Query(ctx, capped)
	if err != nil {
		return Rows{}, false, planError(err)
	}
	defer pgRows.Close()

	out := Rows{}
	for _, fd := range pgRows.FieldDescriptions() {
		out.Columns = append(out.Columns, fd.Name)
	}

	for pgRows.Next() {
		values, err := pgRows.Values()
		if err != nil {
			return Rows{}, false, fmt.Errorf("warehouse: read row: %w", err)
		}
		row := make([]json.RawMessage, 0, len(values))
		for _, v := range values {
			encoded, err := json.Marshal(v)
			if err != nil {
				return Rows{}, false, fmt.Errorf("warehouse: encode value: %w", err)
			}
			row = append(row, encoded)
		}
		out.Rows = append(out.Rows, row)
	}
	if err := pgRows.Err(); err != nil {
		return Rows{}, false, planError(err)
	}

	truncated := len(out.Rows) > rowCap
	if truncated {
		out.Rows = out.Rows[:rowCap]
	}
	return out, truncated, nil
}

// respond renders the result, and takes the handle path if it exceeds the cap.
func (t *QueryTool) respond(
	ctx context.Context,
	p registry.Principal,
	rows Rows,
	truncated bool,
	format ResponseFormat,
	rowCap int,
) (registry.Result, error) {
	rendered, err := rows.Render(format)
	if err != nil {
		return nil, fmt.Errorf("warehouse: render: %w", err)
	}

	if registry.EstimateTokens(rendered) <= t.tokenCap && !truncated {
		return &envelope.ToolsCallResult{
			StructuredContent: rendered,
			Content: []envelope.ContentBlock{{
				Type: "text",
				Text: fmt.Sprintf("%d rows.", len(rows.Rows)),
			}},
		}, nil
	}

	// Over the cap. §8.4: this does NOT truncate silently. The full result
	// becomes a handle and the response carries a summary plus a sample, which
	// is exactly what handles are for.
	full, err := json.Marshal(rows)
	if err != nil {
		return nil, fmt.Errorf("warehouse: encode full result: %w", err)
	}

	handle, err := t.minter.Mint(ctx, p, HandleKindQueryResult, full, t.handleTTL)
	if err != nil {
		return nil, fmt.Errorf("warehouse: the result exceeded this tool's token cap and a "+
			"handle for the full result could not be minted: %w", err)
	}

	sample := rows
	if len(sample.Rows) > inlineSampleRows {
		sample.Rows = sample.Rows[:inlineSampleRows]
	}
	renderedSample, err := sample.Render(format)
	if err != nil {
		return nil, fmt.Errorf("warehouse: render sample: %w", err)
	}

	summary := Summary{
		RowCount:   len(rows.Rows),
		Columns:    rows.Columns,
		Truncated:  truncated,
		SampleRows: len(sample.Rows),
		Handle:     handle,
		Hint: fmt.Sprintf(
			"Narrow the query with a WHERE clause, or request fewer columns. "+
				"The server row cap for this call was %d.", rowCap),
	}

	return &envelope.ToolsCallResult{
		StructuredContent: renderedSample,
		Content: []envelope.ContentBlock{{
			Type: "text",
			Text: summary.TextSummary(),
		}},
	}, nil
}

// planError turns a Postgres error into something a model can act on. A bare
// "ERROR: relation ... does not exist" is technically accurate and practically
// useless when the cause is the empty search_path.
func planError(err error) error {
	msg := err.Error()
	switch {
	case containsAny(msg, "does not exist"):
		return fmt.Errorf("%w — note that the search path is empty, so every table must be "+
			"schema-qualified; try warehouse.orders rather than orders", err)
	case containsAny(msg, "read-only transaction"):
		return &ErrNotReadOnly{Detail: msg}
	case containsAny(msg, "statement timeout", "canceling statement"):
		return fmt.Errorf("the query exceeded the server's statement timeout and was "+
			"cancelled; add a WHERE clause or a smaller LIMIT: %w", err)
	default:
		return err
	}
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		for i := 0; i+len(n) <= len(haystack); i++ {
			if haystack[i:i+len(n)] == n {
				return true
			}
		}
	}
	return false
}
