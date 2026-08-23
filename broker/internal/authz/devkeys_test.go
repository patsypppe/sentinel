package authz

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const devSeed = "6465765f7365656465765f7365656465765f7365656465765f736565646465" + "76"

func devPair(t *testing.T) *DevKeyPair {
	t.Helper()
	k, err := DeriveDevKey(devSeed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestDerivationIsDeterministic. The server and the minter must reach the same
// key from the same seed, or the demo exercises nothing.
func TestDerivationIsDeterministic(t *testing.T) {
	a, err := DeriveDevKey(devSeed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveDevKey(devSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Public.Equal(b.Public) {
		t.Fatal("the same seed produced different keys")
	}
}

func TestDifferentSeedsProduceDifferentKeys(t *testing.T) {
	a := devPair(t)
	b, err := DeriveDevKey(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	if a.Public.Equal(b.Public) {
		t.Fatal("different seeds produced the same key")
	}
}

func TestSeedMustBeTheRightLength(t *testing.T) {
	for _, seed := range []string{"", "ab", strings.Repeat("ab", 16), strings.Repeat("ab", 64), "zz"} {
		if _, err := DeriveDevKey(seed); err == nil {
			t.Errorf("seed %q was accepted", seed)
		}
	}
}

// TestMintedTokenValidatesAgainstTheDerivedKeySet — the round trip the demo
// depends on.
func TestMintedTokenValidatesAgainstTheDerivedKeySet(t *testing.T) {
	k := devPair(t)
	keys, err := k.KeySet()
	if err != nil {
		t.Fatal(err)
	}

	token, err := k.Mint(MintRequest{
		Issuer:      issuer,
		Audience:    thisServer,
		Subject:     "analyst@acme.example",
		PrincipalID: principalID,
		Scopes:      "warehouse:read",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	p, err := Validate(token, Config{
		Issuer: issuer, Audience: thisServer, Keys: keys,
		Leeway: 30 * time.Second, TenantID: tenant,
	}, time.Now())
	if err != nil {
		t.Fatalf("a locally-minted token was rejected by the derived key set: %v", err)
	}
	if p.ID != principalID {
		t.Fatalf("principal = %q", p.ID)
	}
}

// TestMinterCanProduceAWrongAudienceToken.
//
// This is the property that makes the demo possible: to SHOW the MUST NOT, you
// have to be able to mint a token for the wrong audience as easily as for the
// right one. A minter that could only produce acceptable tokens could not
// demonstrate anything.
func TestMinterCanProduceAWrongAudienceTokenAndTheServerRefusesIt(t *testing.T) {
	k := devPair(t)
	keys, err := k.KeySet()
	if err != nil {
		t.Fatal(err)
	}

	wrong, err := k.Mint(MintRequest{
		Issuer:      issuer,
		Audience:    otherServer, // correctly signed, wrong service
		PrincipalID: principalID,
		Scopes:      "warehouse:read",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	_, err = Validate(wrong, Config{
		Issuer: issuer, Audience: thisServer, Keys: keys,
		Leeway: 30 * time.Second, TenantID: tenant,
	}, time.Now())
	if !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("err = %v, want ErrWrongAudience", err)
	}
}

func TestMintRequiresAnExplicitAudience(t *testing.T) {
	k := devPair(t)
	if _, err := k.Mint(MintRequest{Issuer: issuer, PrincipalID: principalID}, time.Now()); err == nil {
		t.Fatal("minting with no audience must be refused: an implicit audience is how a " +
			"token ends up accepted by a service it was not issued for")
	}
}

func TestJWKSRendersThePublicHalfOnly(t *testing.T) {
	k := devPair(t)
	raw, err := k.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "\"d\"") {
		t.Fatalf("the JWKS contains a private key component: %s", raw)
	}
	if !strings.Contains(string(raw), DevKeyID) {
		t.Fatalf("the JWKS does not publish the key id: %s", raw)
	}
}
