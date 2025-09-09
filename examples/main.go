package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	witJWTType = "wit+jwt"
	wptJWTType = "wpt+jwt"
	witIat     = 1745508910
	witExp     = 1745512510
	wptExp     = 1745510016
	subject    = "wimse://example.com/specific-workload"
	audience   = "https://workload.example.com/path"
	rawAT      = "16_mAd0GiwaZokU26_0902100" // arbitrary example
)

func main() {
	if err := generateExamples(); err != nil {
		fmt.Printf("Error: %s\n", err)
	}
}

func generateExamples() error {
	wlAlg := jose.EdDSA

	wlJwkJson :=
        `{
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "1CXXvflN_LVVsIsYXsUvB03JmlGWeCHqQVuouCF92bg",
          "d": "sdLX8yCYKqo_XvGBLn-ZWeKT7llYeeQpgeCaXVxb5kY"
         }`

    wlJwk, err := parseJWK(wlJwkJson)
    if err != nil {
        return fmt.Errorf("failed to parse wl JWK: %w", err)
    }

    wlKeyPriv := wlJwk.Key.(ed25519.PrivateKey)
    wlKeyPub := wlJwk.Public().Key

    signerJwkJson :=
        `{
           "kty": "EC",
           "kid": "June 5",
           "crv": "P-256",
           "x": "kXqnA2Op7hgd4zRMbw0iFcc_hDxUxhojxOFVGjE2gks",
           "y": "n__VndPMR021-59UAs0b9qDTFT-EZtT6xSNs_xFskLo",
           "d": "NRHs9bfMUcF49AV_NIoeh3UGopW4AXZLfv5G2px1WcY"
          }`

    signerJwk, err := parseJWK(signerJwkJson)
	if err != nil {
		return fmt.Errorf("failed to parse authority key: %w", err)
	}

    keySign := signerJwk.Key.(*ecdsa.PrivateKey)

	keySigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: keySign}, (&jose.SignerOptions{}).
		WithType(witJWTType).
		WithHeader("kid", signerJwk.KeyID))
	if err != nil {
		return fmt.Errorf("failed to create WIT signer: %w", err)
	}

	wit := witClaims{
		Id:        "x-_1CTL2cca3CSE4cwb_l",
		Subject:   subject,
		IssuedAt:  witIat,
		ExpiresAt: witExp,
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

	wpt := wptClaims{
		Id:        "__bwc4ESC3acc2LTC1-_x",
		Aud:       audience,
		ExpiresAt: wptExp,
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
		KeyID: signerJwk.KeyID,
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

func base64UrlEncTokenHash(raw string) string {
	if raw == "" {
		return ""
	}

	h := sha256.New()
	h.Write([]byte(raw))

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil))
}

func parseJWK(jwkJSON string) (jwk jose.JSONWebKey, err error) {
	err = json.Unmarshal([]byte(jwkJSON), &jwk)
	if err != nil {
		return jwk, fmt.Errorf("unmarshal JWK: %w", err)
	}
	if !jwk.Valid() {
		return jwk, fmt.Errorf("invalid JWK")
	}
	return jwk, nil
}