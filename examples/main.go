package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	witJWTType = "wimse-id+jwt"
	wptJWTType = "wimse-proof+jwt"
	subject    = "wimse://example.com/specific-workload"
	audience   = "https://workload.example.com/path"
	witTTL     = time.Hour
	wptTTL     = 5 * time.Minute
	keyID      = "June 5"
	rawAT      = "16_mAd0GiwaZokU26_0902100" // arbitrary example
)

func main() {
	if err := generateExamples(); err != nil {
		fmt.Printf("Error: %s\n", err)
	}
}

func generateExamples() error {
	now := time.Now()

	wlAlg := jose.EdDSA
	wlKeyPub, wlKeyPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate wl key: %w", err)
	}

	keySign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate authority key: %w", err)
	}

	keySigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: keySign}, (&jose.SignerOptions{}).
		WithType(witJWTType).
		WithHeader("kid", keyID))
	if err != nil {
		return fmt.Errorf("failed to create WIT signer: %w", err)
	}

	witJTI, err := generateJTI()
	if err != nil {
		return fmt.Errorf("failed to generate jti: %w", err)
	}

	wit := witClaims{
		Id:        witJTI,
		Subject:   subject,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(witTTL).Unix(),
		Cnf: cnf{
			JWK: jose.JSONWebKey{
				Key:       wlKeyPub,
				Algorithm: string(wlAlg),
			},
		},
	}
	witEnc, err := jwt.Signed(keySigner).Claims(wit).Serialize()
	if err != nil {
		return fmt.Errorf("failed to sign WIT: %w", err)
	}

	wptJTI, err := generateJTI()
	if err != nil {
		return fmt.Errorf("failed to generate jti: %w", err)
	}

	wpt := wptClaims{
		Id:        wptJTI,
		Aud:       audience,
		ExpiresAt: now.Add(wptTTL).Unix(),
		Wth:       base64UrlEncTokenHash(witEnc),
		Ath:       base64UrlEncTokenHash(rawAT),
	}

	wlSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: wlAlg, Key: wlKeyPriv}, (&jose.SignerOptions{}).WithType(wptJWTType))
	if err != nil {
		return fmt.Errorf("failed to create WPT signer: %w", err)
	}

	wptEnc, err := jwt.Signed(wlSigner).Claims(wpt).Serialize()
	if err != nil {
		return fmt.Errorf("failed to sign WPT: %w", err)
	}

	fmt.Printf("WIT: %s\n", witEnc)
	fmt.Printf("WPT: %s\n", wptEnc)

	wlPrivJwk := jose.JSONWebKey{
		Key: wlKeyPriv,
	}
	if wlPrivJwkStr, err := json.MarshalIndent(wlPrivJwk, "", " "); err == nil {
		fmt.Printf("WL private key: %s\n", wlPrivJwkStr)
	}

	signerPubJwk := jose.JSONWebKey{
		Key:   keySign.Public(),
		KeyID: keyID,
	}
	if signerPubJwkStr, err := json.MarshalIndent(signerPubJwk, "", " "); err == nil {
		fmt.Printf("Signer public key: %s\n", signerPubJwkStr)
	}

	return nil
}

type witClaims struct {
	ExpiresAt int64  `json:"exp,omitempty"`
	Id        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Cnf       cnf    `json:"cnf,omitempty"`
}

type wptClaims struct {
	Aud       interface{} `json:"aud,omitempty"`
	ExpiresAt int64       `json:"exp,omitempty"`
	Id        string      `json:"jti,omitempty"`
	Wth       string      `json:"wth,omitempty"`
	Ath       string      `json:"ath,omitempty"`
	Tth       string      `json:"tth,omitempty"`
	Oth       string      `json:"oth,omitempty"`
}

type cnf struct {
	JWK jose.JSONWebKey `json:"jwk"`
}

func generateJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func base64UrlEncTokenHash(raw string) string {
	if raw == "" {
		return ""
	}

	h := sha256.New()
	h.Write([]byte(raw))

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil))
}
