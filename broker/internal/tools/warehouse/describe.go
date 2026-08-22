package warehouse

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/patsypppe/sentinel/broker/internal/envelope"
	"github.com/patsypppe/sentinel/broker/internal/registry"
)

// DescribeTool is warehouse.describe: the schema of the tables this principal
// can actually read.
//
// It lists only permitted relations, and that is a design decision rather than
// a convenience. Describing a table the caller cannot query would turn the
// schema endpoint into an enumeration oracle for the ones they cannot — the same
// reasoning that makes handle resolution return one indistinguishable error.
type DescribeTool struct {
	pool *pgxpool.Pool
}

func NewDescribeTool(pool *pgxpool.Pool) *DescribeTool { return &DescribeTool{pool: pool} }

func (t *DescribeTool) Name() string { return "warehouse.describe" }

func (t *DescribeTool) Description() string {
	return "List the warehouse tables your scopes permit you to read, with their columns " +
		"and types. Use this before warehouse.query to get exact, schema-qualified names."
}

func (t *DescribeTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
      "type": "object",
      "properties": {
        "table": {
          "type": "string",
          "description": "Optional schema-qualified table, e.g. warehouse.orders. Omit for all readable tables."
        },
        "response_format": {
          "type": "string",
          "enum": ["concise", "detailed"],
          "default": "concise"
        }
      },
      "additionalProperties": false
    }`)
}

func (t *DescribeTool) OutputSchema() json.RawMessage {
	return json.RawMessage(`{
      "type": "object",
      "properties": {
        "tables": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "name": {"type": "string"},
              "columns": {
                "type": "array",
                "items": {
                  "type": "object",
                  "properties": {
                    "name": {"type": "string"},
                    "type": {"type": "string"},
                    "nullable": {"type": "boolean"}
                  },
                  "required": ["name", "type"]
                }
              }
            },
            "required": ["name", "columns"]
          }
        }
      },
      "required": ["tables"]
    }`)
}

func (t *DescribeTool) Scopes() []string { return []string{"warehouse:describe"} }

func (t *DescribeTool) Reversibility() registry.Reversibility { return registry.Reversible }

// CachePolicy: schema changes rarely, but WHICH tables are visible depends on
// the caller's scopes, so it is private with a longer TTL than query results.
func (t *DescribeTool) CachePolicy() envelope.CachePolicy {
	return envelope.CachePolicy{TTLMs: 300_000, Scope: envelope.ScopePrivate}
}

func (t *DescribeTool) TokenCap() int { return 25_000 }

type column struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
}

type table struct {
	Name    string   `json:"name"`
	Columns []column `json:"columns"`
}

type describeResult struct {
	Tables []table `json:"tables"`
}

type describeArgs struct {
	Table          string `json:"table"`
	ResponseFormat string `json:"response_format"`
}

func (t *DescribeTool) Call(ctx context.Context, p registry.Principal, raw json.RawMessage) (registry.Result, error) {
	var args describeArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, fmt.Errorf("%q could not be parsed as an object: %w", "arguments", err)
		}
	}
	if _, err := ParseResponseFormat(args.ResponseFormat); err != nil {
		return nil, err
	}

	// The allowlist comes from warehouse:read, not warehouse:describe: this
	// endpoint describes what you could query, so the two must not diverge.
	allow := AllowlistFor(p.Scopes)
	permitted := allow.Relations()
	if len(permitted) == 0 {
		return nil, fmt.Errorf(
			"your scopes %v grant no readable relations; warehouse.describe needs \"warehouse:read\"",
			p.Scopes)
	}

	if args.Table != "" && !containsString(permitted, args.Table) {
		// Same error whether the table does not exist or is not permitted. A
		// distinguishable answer here would enumerate the schema.
		return nil, &ErrRelationDenied{Relation: args.Table, Permitted: permitted}
	}
	if args.Table != "" {
		permitted = []string{args.Table}
	}

	tables, err := t.describe(ctx, permitted)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(describeResult{Tables: tables})
	if err != nil {
		return nil, fmt.Errorf("warehouse: encode schema: %w", err)
	}

	return &envelope.ToolsCallResult{
		StructuredContent: payload,
		Content: []envelope.ContentBlock{{
			Type: "text",
			Text: fmt.Sprintf("%d readable table(s).", len(tables)),
		}},
	}, nil
}

const describeSQL = `
SELECT c.table_schema || '.' || c.table_name AS relation,
       c.column_name,
       c.data_type,
       c.is_nullable = 'YES' AS nullable
  FROM information_schema.columns AS c
 WHERE c.table_schema || '.' || c.table_name = ANY($1)
 ORDER BY relation, c.ordinal_position`

func (t *DescribeTool) describe(ctx context.Context, relations []string) ([]table, error) {
	tx, err := t.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("warehouse: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The relation list is bound as a parameter, never interpolated. It is
	// server-derived rather than caller-supplied, but a server-derived value
	// interpolated today is a caller-supplied one after the next refactor.
	rows, err := tx.Query(ctx, describeSQL, relations)
	if err != nil {
		return nil, fmt.Errorf("warehouse: describe: %w", err)
	}
	defer rows.Close()

	byTable := map[string][]column{}
	for rows.Next() {
		var relation string
		var col column
		if err := rows.Scan(&relation, &col.Name, &col.Type, &col.Nullable); err != nil {
			return nil, fmt.Errorf("warehouse: scan column: %w", err)
		}
		byTable[relation] = append(byTable[relation], col)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("warehouse: iterate columns: %w", err)
	}

	names := make([]string, 0, len(byTable))
	for name := range byTable {
		names = append(names, name)
	}
	// Sorted so the result is deterministic; map iteration is not.
	sort.Strings(names)

	out := make([]table, 0, len(names))
	for _, name := range names {
		out = append(out, table{Name: name, Columns: byTable[name]})
	}
	return out, nil
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
