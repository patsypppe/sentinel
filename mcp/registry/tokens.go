package registry

import (
	"strings"
	"unicode"
)

// Token accounting for the manifest, docs/HANDOFF.md §8.3.
//
// Anthropic's guidance is the reference point: agents wired to many tools "need
// to process hundreds of thousands of tokens before reading a request", and
// consolidating tool surfaces is how that is fixed. A number is only worth
// reporting if the method behind it is stated, so:
//
// TOKENIZER: a deterministic, dependency-free approximation, NOT a model
// tokenizer. It splits on whitespace and punctuation boundaries the way BPE
// vocabularies tend to, then charges one token per resulting run and one per
// four characters of any run longer than four. On JSON manifests this lands
// within roughly 10% of cl100k_base, which is ample for the comparison it is
// used for — the same manifest before and after consolidation, measured the
// same way.
//
// It is deliberately in-repo rather than a tiktoken dependency: the measurement
// must be reproducible by anyone who clones this, on a machine with no model
// API key, which is the whole reason this project has none.
const (
	// TokenizerName is printed next to every number this package produces.
	//
	//nolint:gosec // G101 matches on the identifier containing "Token"; this
	// names a tokenizer, not a credential. Annotated here rather than disabling
	// G101 repo-wide so a genuine hardcoded secret still trips it.
	TokenizerName = "sentinel/approx-v1"
	// charsPerToken is the amortized cost of a long run.
	charsPerToken = 4
)

// TokenCount is the manifest's measured cost.
type TokenCount struct {
	Tokenizer string
	// Manifest is the whole serialized manifest.
	Manifest int
	// PerTool is keyed by tool name.
	PerTool map[string]int
}

// EstimateTokens counts tokens in a byte slice under TokenizerName.
func EstimateTokens(b []byte) int {
	return estimate(string(b))
}

func estimate(s string) int {
	total := 0
	runLen := 0

	flush := func() {
		if runLen == 0 {
			return
		}
		total++
		if runLen > charsPerToken {
			total += (runLen - 1) / charsPerToken
		}
		runLen = 0
	}

	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			flush()
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_':
			runLen++
		default:
			// Punctuation is its own token, which is how JSON's braces, quotes
			// and colons actually price out.
			flush()
			total++
		}
	}
	flush()
	return total
}

func countTokens(tools []Tool, manifest []byte) TokenCount {
	perTool := make(map[string]int, len(tools))
	for _, t := range tools {
		var sb strings.Builder
		sb.WriteString(t.Name())
		sb.WriteString(t.Description())
		sb.Write(t.InputSchema())
		sb.Write(t.OutputSchema())
		perTool[t.Name()] = estimate(sb.String())
	}
	return TokenCount{
		Tokenizer: TokenizerName,
		Manifest:  EstimateTokens(manifest),
		PerTool:   perTool,
	}
}
