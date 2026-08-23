package authz

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// A deterministic development keypair.
//
// docs/HANDOFF.md §3.2 puts full OAuth out of scope and says to "demo with a
// static issuer and a locally-minted token". Deriving the keypair from a
// configured seed makes that possible with no key files to distribute: the
// server and the token minter reach the same key from the same seed, so the
// demo and the end-to-end tests exercise the REAL validation path rather than a
// bypass.
//
// It is development-only and says so everywhere it appears. A seed in an
// environment variable is a private key in an environment variable; the
// production path is BROKER_OAUTH_JWKS_PATH, which this does not touch.

// DevKeyID is the kid the derived key is published under.
const DevKeyID = "sentinel-dev-key"

// DevKeyPair is a keypair derived from a seed.
type DevKeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// DeriveDevKey builds a keypair from a hex-encoded 32-byte seed.
func DeriveDevKey(hexSeed string) (*DevKeyPair, error) {
	seed, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, fmt.Errorf("authz: dev seed is not valid hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("authz: dev seed is %d bytes, want %d",
			len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("authz: derived key is not ed25519")
	}
	return &DevKeyPair{Private: priv, Public: pub}, nil
}

// KeySet publishes the derived public key as a JWKS-backed key set.
func (k *DevKeyPair) KeySet() (*StaticKeySet, error) {
	raw, err := json.Marshal(jwkSet{Keys: []jwk{{
		Kty: "OKP", Kid: DevKeyID, Alg: "EdDSA", Use: "sig", Crv: "Ed25519",
		X: base64.RawURLEncoding.EncodeToString(k.Public),
	}}})
	if err != nil {
		return nil, fmt.Errorf("authz: encode dev jwks: %w", err)
	}
	return ParseKeySet(raw)
}

// JWKS renders the public half as a JWKS document, so an operator can see
// exactly what the server will accept.
func (k *DevKeyPair) JWKS() ([]byte, error) {
	return json.MarshalIndent(jwkSet{Keys: []jwk{{
		Kty: "OKP", Kid: DevKeyID, Alg: "EdDSA", Use: "sig", Crv: "Ed25519",
		X: base64.RawURLEncoding.EncodeToString(k.Public),
	}}}, "", "  ")
}

// MintRequest describes a token to mint.
type MintRequest struct {
	Issuer      string
	Audience    string
	Subject     string
	PrincipalID string
	Scopes      string
	TTL         time.Duration
}

// Mint issues a token.
//
// The audience is a plain parameter with no default, which is the point: to
// demonstrate the MUST NOT, someone has to be able to mint a token for the
// WRONG audience as easily as for the right one, and watch this server refuse
// it. A minter that could only produce acceptable tokens could not show that.
func (k *DevKeyPair) Mint(req MintRequest, now time.Time) (string, error) {
	if req.TTL <= 0 {
		req.TTL = time.Hour
	}
	if req.Audience == "" {
		return "", errors.New("authz: mint requires an explicit audience")
	}
	if req.PrincipalID == "" {
		return "", errors.New("authz: mint requires a principal id")
	}

	claims := Claims{
		Issuer:      req.Issuer,
		Subject:     req.Subject,
		Audience:    []string{req.Audience},
		ExpiresAt:   now.Add(req.TTL).Unix(),
		IssuedAt:    now.Unix(),
		NotBefore:   now.Unix(),
		Scopes:      req.Scopes,
		PrincipalID: req.PrincipalID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = DevKeyID

	signed, err := token.SignedString(k.Private)
	if err != nil {
		return "", fmt.Errorf("authz: sign token: %w", err)
	}
	return signed, nil
}
