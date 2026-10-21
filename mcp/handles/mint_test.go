package handles

import (
	"strings"
	"testing"
)

// TestHandleIsCSPRNG. §7.4 requires 128 bits from a CSPRNG with no sequential
// structure. A handle is not a credential, but a guessable one lets an attacker
// probe the space, and the indistinguishable-error rule removes the ORACLE, not
// the guessing.
func TestHandleIsCSPRNG(t *testing.T) {
	const n = 2000

	seen := make(map[string]bool, n)
	ids := make([]string, 0, n)

	for i := 0; i < n; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("collision after %d mints: %s", i, id)
		}
		seen[id] = true
		ids = append(ids, id)
	}

	// 128 bits of base32 is 26 characters, plus the prefix.
	const wantLen = len(Prefix) + 26
	for _, id := range ids[:10] {
		if len(id) != wantLen {
			t.Fatalf("handle %q is %d characters, want %d (128 bits of base32)",
				id, len(id), wantLen)
		}
		if !strings.HasPrefix(id, Prefix) {
			t.Fatalf("handle %q lacks the %q prefix", id, Prefix)
		}
	}
}

// TestHandlesHaveNoSequentialStructure. The failure this catches is a counter
// or a timestamp leaking into the identifier: consecutive mints would then
// share a long prefix, and an attacker holding one handle could enumerate its
// neighbours.
func TestHandlesHaveNoSequentialStructure(t *testing.T) {
	const n = 500

	prev, err := NewID()
	if err != nil {
		t.Fatal(err)
	}

	longestShared := 0
	for i := 0; i < n; i++ {
		next, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		if shared := sharedPrefix(prev[len(Prefix):], next[len(Prefix):]); shared > longestShared {
			longestShared = shared
		}
		prev = next
	}

	// With 32 symbols per position, consecutive random handles share more than
	// six leading characters with probability around 32^-7, i.e. never. A
	// counter or a timestamp would blow straight through this.
	if longestShared > 6 {
		t.Fatalf("consecutive handles shared %d leading characters; that is a counter or a "+
			"timestamp leaking into the identifier, not entropy", longestShared)
	}
}

func sharedPrefix(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}

// TestEntropyIsSpreadAcrossThePosition. A generator that varied only its tail
// would pass the two tests above; this one looks at each position independently.
func TestEntropyIsSpreadAcrossEveryPosition(t *testing.T) {
	const n = 1000
	const positions = 26

	distinct := make([]map[byte]bool, positions)
	for i := range distinct {
		distinct[i] = map[byte]bool{}
	}

	for i := 0; i < n; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		body := id[len(Prefix):]
		for pos := 0; pos < positions && pos < len(body); pos++ {
			distinct[pos][body[pos]] = true
		}
	}

	// Base32 packs 5 bits per character, and 128 bits is not a multiple of 5.
	// The first 25 characters carry 125 bits; the 26th carries the remaining
	// THREE, so it can only ever take 2^3 = 8 of the 32 symbols. That is a
	// property of the encoding, not a weakness in the generator — the identifier
	// still carries its full 128 bits.
	//
	// Asserting the exact figure rather than relaxing the threshold means a
	// change to entropyBytes or to the encoding fails here with an explanation,
	// instead of silently passing a looser bound.
	const lastPosition = positions - 1
	const residualSymbols = 8

	for pos, symbols := range distinct {
		if pos == lastPosition {
			if len(symbols) != residualSymbols {
				t.Errorf("the final character took %d distinct symbols, want exactly %d: "+
					"128 bits leaves 3 bits for the 26th base32 character. If entropyBytes "+
					"or the encoding changed, this arithmetic changed with it",
					len(symbols), residualSymbols)
			}
			continue
		}
		// Over 1000 samples a fully random base32 position should show almost
		// all 32 symbols. Fewer than 16 means that position is not random.
		if len(symbols) < 16 {
			t.Errorf("position %d took only %d distinct symbols across %d mints; entropy is "+
				"not spread across the identifier", pos, len(symbols), n)
		}
	}
}

// TestHandleCarriesTheFullEntropyBudget states the arithmetic the test above
// depends on, so the two cannot drift apart silently.
func TestHandleCarriesTheFullEntropyBudget(t *testing.T) {
	const bitsPerBase32Char = 5

	bits := entropyBytes * 8
	if bits < 128 {
		t.Fatalf("handles carry %d bits of entropy, want at least 128 (§7.4)", bits)
	}

	chars := (bits + bitsPerBase32Char - 1) / bitsPerBase32Char
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(id) - len(Prefix); got != chars {
		t.Fatalf("handle body is %d characters, want %d for %d bits of base32",
			got, chars, bits)
	}
}

func TestBindingIsPrincipalAndHandle(t *testing.T) {
	got := Binding("principal-1", "hnd_ABC")
	if got != "principal-1:hnd_ABC" {
		t.Fatalf("Binding = %q", got)
	}
}
