package mrtr

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func testSealer(t *testing.T) *Sealer {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSealRoundTrips(t *testing.T) {
	s := testSealer(t)
	expiry := time.Now().Add(5 * time.Minute).Truncate(time.Second)

	sealed, err := s.Seal("corr-abc-123", expiry, "ops.deployment_apply")
	if err != nil {
		t.Fatal(err)
	}

	id, gotExpiry, err := s.Unseal(sealed, "ops.deployment_apply")
	if err != nil {
		t.Fatal(err)
	}
	if id != "corr-abc-123" {
		t.Fatalf("correlation id = %q", id)
	}
	if !gotExpiry.Equal(expiry) {
		t.Fatalf("expiry = %s, want %s", gotExpiry, expiry)
	}
}

// TestTamperedRequestStateRejected — one of the nine negative tests of §11.
//
// Every byte position is flipped in turn. An AEAD gives an all-or-nothing
// guarantee, so a test that only mutated the first byte would pass against a
// scheme that authenticated just a prefix.
func TestTamperedRequestStateRejected(t *testing.T) {
	s := testSealer(t)
	sealed, err := s.Seal("corr-abc-123", time.Now().Add(time.Hour), "ops.deployment_apply")
	if err != nil {
		t.Fatal(err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}

	for i := range raw {
		mutated := make([]byte, len(raw))
		copy(mutated, raw)
		mutated[i] ^= 0x01

		_, _, err := s.Unseal(base64.RawURLEncoding.EncodeToString(mutated), "ops.deployment_apply")
		if !errors.Is(err, ErrStateInvalid) {
			t.Fatalf("flipping a bit at byte %d/%d produced err = %v, want ErrStateInvalid",
				i, len(raw), err)
		}
	}
}

// TestForgedRequestStateRejected. Nothing a client can construct without the
// key verifies.
func TestForgedRequestStateRejected(t *testing.T) {
	s := testSealer(t)

	forgeries := []string{
		"",
		"not-base64!!!",
		base64.RawURLEncoding.EncodeToString([]byte("short")),
		base64.RawURLEncoding.EncodeToString(make([]byte, 200)),
		// What a base64-of-JSON scheme would have accepted — the shape §14
		// gotcha 6 warns against.
		base64.RawURLEncoding.EncodeToString([]byte(`{"correlationId":"corr-abc-123","expiry":9999999999}`)),
	}
	for _, f := range forgeries {
		if _, _, err := s.Unseal(f, "ops.deployment_apply"); !errors.Is(err, ErrStateInvalid) {
			t.Errorf("forgery %q produced err = %v, want ErrStateInvalid", f, err)
		}
	}
}

// TestSealedStateCannotBeReplayedAgainstAnotherTool. The tool name is the
// AEAD's additional authenticated data, so a state sealed for one tool fails to
// verify for any other. §14 gotcha 6: forgetting this binding is a listed
// pitfall.
func TestSealedStateCannotBeReplayedAgainstAnotherTool(t *testing.T) {
	s := testSealer(t)

	sealed, err := s.Seal("corr-abc-123", time.Now().Add(time.Hour), "ops.deployment_apply")
	if err != nil {
		t.Fatal(err)
	}

	for _, other := range []string{
		"warehouse.query",
		"ops.deployment_plan",
		"ops.deployment_appl",   // one character short
		"ops.deployment_applyy", // one character long
		"",
	} {
		if _, _, err := s.Unseal(sealed, other); !errors.Is(err, ErrStateInvalid) {
			t.Errorf("a state sealed for ops.deployment_apply unsealed for %q (err = %v)", other, err)
		}
	}
}

// TestAnotherServersKeyDoesNotUnseal. Two brokers with different keys must not
// accept each other's states, or a flow approved on one is executable on the
// other.
func TestAnotherServersKeyDoesNotUnseal(t *testing.T) {
	mine, theirs := testSealer(t), testSealer(t)

	sealed, err := mine.Seal("corr-abc-123", time.Now().Add(time.Hour), "ops.deployment_apply")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := theirs.Unseal(sealed, "ops.deployment_apply"); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("another key unsealed the state (err = %v)", err)
	}
}

func TestExpiredStateIsRejected(t *testing.T) {
	s := testSealer(t)

	sealed, err := s.Seal("corr-abc-123", time.Now().Add(-time.Minute), "ops.deployment_apply")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Unseal(sealed, "ops.deployment_apply"); !errors.Is(err, ErrStateExpired) {
		t.Fatalf("err = %v, want ErrStateExpired", err)
	}
}

// TestExpiryIsCheckedAfterTheTag. Checking expiry first would let an attacker
// distinguish "expired" from "forged", and the sealed expiry is not trustworthy
// until the tag says it is.
func TestExpiryIsCheckedAfterTheTag(t *testing.T) {
	s := testSealer(t)

	sealed, err := s.Seal("corr-abc-123", time.Now().Add(-time.Hour), "ops.deployment_apply")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01 // corrupt the tag on an already-expired state

	_, _, err = s.Unseal(base64.RawURLEncoding.EncodeToString(raw), "ops.deployment_apply")
	if !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("err = %v, want ErrStateInvalid: an expired-AND-corrupt state must report "+
			"the corruption, or the expiry check is running on unauthenticated bytes", err)
	}
}

// TestNoncesAreUnique. XChaCha20-Poly1305's 192-bit nonce is chosen precisely so
// random nonces do not collide — there is no counter to keep across restarts,
// which a stateless server could not keep anyway.
func TestNoncesAreUnique(t *testing.T) {
	s := testSealer(t)
	expiry := time.Now().Add(time.Hour)

	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		sealed, err := s.Seal("corr-abc-123", expiry, "ops.deployment_apply")
		if err != nil {
			t.Fatal(err)
		}
		if seen[sealed] {
			t.Fatalf("sealing the same value twice produced identical output at iteration %d; "+
				"the nonce is not random", i)
		}
		seen[sealed] = true
	}
}

func TestSealRejectsAnEmptyToolName(t *testing.T) {
	s := testSealer(t)
	_, err := s.Seal("corr-abc-123", time.Now().Add(time.Hour), "")
	if err == nil {
		t.Fatal("an empty tool name binds nothing and must be refused: it removes the " +
			"cross-tool protection rather than weakening it")
	}
	if !strings.Contains(err.Error(), "additional data") {
		t.Fatalf("error %q should explain why the tool name matters", err)
	}
}

func TestKeyMustBeTheRightSize(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewSealer(make([]byte, n)); err == nil {
			t.Errorf("a %d-byte key was accepted, want %d", n, KeySize)
		}
	}
}

// TestRequestStateIsOpaque. A client stores and returns it without
// understanding it; if the correlation id were readable, clients would start
// depending on it and the seal would become decorative.
func TestRequestStateIsOpaque(t *testing.T) {
	s := testSealer(t)
	sealed, err := s.Seal("corr-SECRET-VALUE", time.Now().Add(time.Hour), "ops.deployment_apply")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "SECRET") {
		t.Fatalf("the correlation id is readable in %q", sealed)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(decoded), "SECRET") {
		t.Fatalf("the correlation id is readable after one base64 decode: %q", decoded)
	}
}
