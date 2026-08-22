package warehouse

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Tool response discipline, docs/HANDOFF.md §8.4. Three mechanisms, all here:
//
//  1. response_format: concise | detailed, a standard argument on every tool
//     that can return variable-size output.
//  2. A hard token cap per tool. Exceeding it does NOT truncate silently: the
//     tool returns a handle to the full result plus a summary, which is exactly
//     what handles are for.
//  3. Actionable errors — see actionable.go.

// ResponseFormat controls how much of a result is inlined.
type ResponseFormat string

const (
	// FormatConcise is the default. Values only, no per-row key repetition.
	FormatConcise ResponseFormat = "concise"
	// FormatDetailed inlines every row as a keyed object.
	FormatDetailed ResponseFormat = "detailed"
)

// ParseResponseFormat validates the argument, defaulting to concise.
func ParseResponseFormat(s string) (ResponseFormat, error) {
	switch s {
	case "":
		return FormatConcise, nil
	case string(FormatConcise):
		return FormatConcise, nil
	case string(FormatDetailed):
		return FormatDetailed, nil
	default:
		return "", fmt.Errorf(
			"%q must be one of \"concise\" or \"detailed\"; got %q; try \"concise\"",
			"response_format", s)
	}
}

// Rows is a result set held column-major-ish: a column list plus row tuples.
// Keeping the columns out of every row is most of what makes concise concise.
type Rows struct {
	Columns []string            `json:"columns"`
	Rows    [][]json.RawMessage `json:"rows"`
}

// Render produces the payload for a response format.
//
// concise emits `{"columns": [...], "rows": [[...], ...]}` — the column names
// appear once. detailed emits `[{"col": value, ...}, ...]` — every row repeats
// every key. On a 20-row, 5-column result that difference is 100 repeated key
// strings, which is the entire mechanism: Anthropic measured a Slack response
// dropping from 206 tokens to 72 with this one change, and the shape of the
// saving is the same here.
func (r Rows) Render(format ResponseFormat) (json.RawMessage, error) {
	if format == FormatDetailed {
		objects := make([]map[string]json.RawMessage, 0, len(r.Rows))
		for _, row := range r.Rows {
			obj := make(map[string]json.RawMessage, len(r.Columns))
			for i, col := range r.Columns {
				if i < len(row) {
					obj[col] = row[i]
				}
			}
			objects = append(objects, obj)
		}
		return json.Marshal(objects)
	}
	return json.Marshal(r)
}

// Summary is what accompanies a handle when a result exceeds its token cap. It
// has to be enough for a model to decide whether the full result is worth
// fetching, which means shape and a sample, not just a count.
type Summary struct {
	RowCount   int      `json:"rowCount"`
	Columns    []string `json:"columns"`
	Truncated  bool     `json:"truncated"`
	SampleRows int      `json:"sampleRows"`
	Handle     string   `json:"handle"`
	Hint       string   `json:"hint"`
}

// TextSummary is the human/model-readable line accompanying an overflow.
func (s Summary) TextSummary() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d rows across %d columns (%s) exceeded this tool's token cap. ",
		s.RowCount, len(s.Columns), strings.Join(s.Columns, ", "))
	fmt.Fprintf(&sb, "The first %d rows are inlined above; the full result is held as handle %q. ",
		s.SampleRows, s.Handle)
	sb.WriteString(s.Hint)
	return sb.String()
}
