package warehouse

import (
	"encoding/json"
	"testing"

	"github.com/patsypppe/sentinel/broker/internal/registry"
)

func sampleRows(n int) Rows {
	r := Rows{Columns: []string{"order_id", "customer_id", "status", "total_cents", "placed_at"}}
	for i := 0; i < n; i++ {
		r.Rows = append(r.Rows, []json.RawMessage{
			json.RawMessage(`1001`),
			json.RawMessage(`42`),
			json.RawMessage(`"delivered"`),
			json.RawMessage(`12900`),
			json.RawMessage(`"2026-08-21T10:00:00Z"`),
		})
	}
	return r
}

func measure(t *testing.T, n int) (concise, detailed int) {
	t.Helper()
	rows := sampleRows(n)
	c, err := rows.Render(FormatConcise)
	if err != nil {
		t.Fatal(err)
	}
	d, err := rows.Render(FormatDetailed)
	if err != nil {
		t.Fatal(err)
	}
	return registry.EstimateTokens(c), registry.EstimateTokens(d)
}

// TestConciseIsSmallerThanDetailed is the §8.4 measurement. The mechanism is
// that concise names each column once instead of once per row, so the saving
// grows with row count — which is exactly when it matters.
//
// It starts at TWO rows, not one, and that is a real finding rather than a
// convenient bound. At a single row, concise is LARGER: the standalone column
// list is pure overhead when there is exactly one row to amortize it over.
// TestConciseCrossoverIsAtTwoRows pins the crossover so it is documented rather
// than discovered later by someone measuring a one-row result and concluding the
// mechanism does not work.
func TestConciseIsSmallerThanDetailed(t *testing.T) {
	for _, n := range []int{2, 5, 20, 100} {
		c, d := measure(t, n)
		if c >= d {
			t.Errorf("%d rows: concise (%d tokens) is not smaller than detailed (%d tokens)", n, c, d)
		}
		t.Logf("%3d rows: concise %5d tokens, detailed %5d tokens, saving %4.1f%%",
			n, c, d, 100*float64(d-c)/float64(d))
		// A machine-readable marker consumed by scripts/measure.py. It is a
		// deliberate contract, not debug output: MEASUREMENTS.md reports these
		// numbers, and computing them from the same code the test asserts on
		// means the published figure and the tested figure cannot drift.
		t.Logf("MEASURE response_format rows=%d concise=%d detailed=%d", n, c, d)
	}
}

// TestConciseCrossoverIsAtTwoRows documents the one case where the default
// format costs more than the alternative.
//
// It is left as-is rather than special-cased. Switching shape based on row
// count would make the response schema depend on the data, which is a far worse
// property for a model to consume than a handful of wasted tokens on a result
// that is tiny by definition.
func TestConciseCrossoverIsAtTwoRows(t *testing.T) {
	c1, d1 := measure(t, 1)
	if c1 <= d1 {
		t.Fatalf("one row: concise (%d) is no longer larger than detailed (%d); the crossover "+
			"moved, so this test and the comment on it are now stale", c1, d1)
	}
	t.Logf("  1 row : concise %d tokens, detailed %d tokens — concise costs %d more", c1, d1, c1-d1)

	c2, d2 := measure(t, 2)
	if c2 >= d2 {
		t.Fatalf("two rows: concise (%d) is not yet smaller than detailed (%d); the crossover "+
			"is later than documented", c2, d2)
	}
	t.Logf("  2 rows: concise %d tokens, detailed %d tokens — concise wins from here on", c2, d2)
}

// TestSavingGrowsWithRowCount. If the saving were constant, the mechanism would
// not be doing what it claims — it is per-row key repetition being removed.
func TestSavingGrowsWithRowCount(t *testing.T) {
	saving := func(n int) int {
		rows := sampleRows(n)
		c, _ := rows.Render(FormatConcise)
		d, _ := rows.Render(FormatDetailed)
		return registry.EstimateTokens(d) - registry.EstimateTokens(c)
	}
	small, large := saving(5), saving(100)
	if large <= small*10 {
		t.Fatalf("saving at 100 rows (%d) is not proportional to the saving at 5 rows (%d); "+
			"the mechanism is removing per-row key repetition, so it should scale with rows",
			large, small)
	}
}

func TestBothFormatsRoundTrip(t *testing.T) {
	rows := sampleRows(3)

	concise, err := rows.Render(FormatConcise)
	if err != nil {
		t.Fatal(err)
	}
	var back Rows
	if err := json.Unmarshal(concise, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Rows) != 3 || len(back.Columns) != 5 {
		t.Fatalf("concise did not round-trip: %d rows, %d columns", len(back.Rows), len(back.Columns))
	}

	detailed, err := rows.Render(FormatDetailed)
	if err != nil {
		t.Fatal(err)
	}
	var objects []map[string]json.RawMessage
	if err := json.Unmarshal(detailed, &objects); err != nil {
		t.Fatal(err)
	}
	if len(objects) != 3 {
		t.Fatalf("detailed did not round-trip: %d objects", len(objects))
	}
	if _, ok := objects[0]["status"]; !ok {
		t.Fatal("detailed rows must be keyed by column name")
	}
}

func TestParseResponseFormatDefaultsToConcise(t *testing.T) {
	got, err := ParseResponseFormat("")
	if err != nil {
		t.Fatal(err)
	}
	if got != FormatConcise {
		t.Fatalf("default = %q, want concise: the cheap option is the default", got)
	}
}

// TestParseResponseFormatErrorIsActionable. §8.4: "invalid argument" is a bug.
// The model reads these and retries on them, so they are part of the interface.
func TestParseResponseFormatErrorIsActionable(t *testing.T) {
	_, err := ParseResponseFormat("verbose")
	if err == nil {
		t.Fatal("an unknown response format must be rejected")
	}
	msg := err.Error()
	for _, want := range []string{"response_format", "verbose", "concise", "detailed", "try"} {
		if !contains(msg, want) {
			t.Errorf("error %q does not mention %q; it must name the field, show what "+
				"arrived, and show what would work", msg, want)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}

func TestSummaryTextNamesTheHandleAndTheShape(t *testing.T) {
	s := Summary{
		RowCount:   5000,
		Columns:    []string{"order_id", "status"},
		Truncated:  true,
		SampleRows: 20,
		Handle:     "hnd_ABC123",
		Hint:       "Pass it to warehouse.fetch, or narrow the query with a WHERE clause.",
	}
	text := s.TextSummary()
	for _, want := range []string{"5000", "hnd_ABC123", "order_id", "20", "narrow"} {
		if !contains(text, want) {
			t.Errorf("summary %q omits %q; a model has to decide from this whether the "+
				"full result is worth fetching", text, want)
		}
	}
}
