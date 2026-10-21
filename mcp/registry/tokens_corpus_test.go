package registry

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
)

// TestTokenizerCorpus is the Go half of a cross-language differential test.
//
// The harness ships a Python port of this package's tokenizer, because the
// broker can only tokenize the manifest it was compiled with and the harness
// must price a foreign server's manifest with no Go toolchain present. Two
// implementations of one method is exactly the situation where a number drifts
// silently, so the corpus below is the contract between them.
//
// This test emits MEASURE markers that scripts/measure.py parses, in the same
// way TestConciseIsSmallerThanDetailed does: the published figure is computed
// by the code the test asserts on, never recomputed alongside it.
//
// Regenerate the expected column with:
//
//	go test ./broker/internal/registry -run TestTokenizerCorpus -v
func TestTokenizerCorpus(t *testing.T) {
	const corpusPath = "../../../tests/harness/data/tokenizer_corpus.jsonl"

	fh, err := os.Open(corpusPath)
	if err != nil {
		t.Skipf("corpus not present at %s: %v", corpusPath, err)
	}
	defer func() { _ = fh.Close() }()

	type row struct {
		Why      string `json:"why"`
		Text     string `json:"text"`
		Expected *int   `json:"expected"`
	}

	scanner := bufio.NewScanner(fh)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)

	seen, mismatched := 0, 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var r row
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("corpus line %d is not valid JSON: %v", seen+1, err)
		}
		got := estimate(r.Text)
		seen++
		if r.Expected == nil {
			t.Errorf("corpus row %q carries no expected count; regenerate it", r.Why)
			mismatched++
			continue
		}
		if got != *r.Expected {
			mismatched++
			t.Errorf("case %q: Go counted %d, corpus records %d for %q",
				r.Why, got, *r.Expected, r.Text)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading corpus: %v", err)
	}
	if seen == 0 {
		t.Fatal("corpus is empty; the differential test would pass vacuously")
	}

	// Parsed by scripts/measure.py. Keep the key names stable.
	t.Logf("MEASURE tokenizer_corpus cases=%d mismatched=%d", seen, mismatched)
}
