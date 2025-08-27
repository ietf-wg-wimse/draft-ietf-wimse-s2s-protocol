package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/yaronf/httpsign"
)

type witClaims struct {
	Issuer    string `json:"iss,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Id        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Cnf       cnf    `json:"cnf,omitempty"`
}

type wptClaims struct {
	Aud       interface{}       `json:"aud,omitempty"`
	ExpiresAt int64             `json:"exp,omitempty"`
	Id        string            `json:"jti,omitempty"`
	Wth       string            `json:"wth,omitempty"`
	Ath       string            `json:"ath,omitempty"`
	Tth       string            `json:"tth,omitempty"`
	Oth       map[string]string `json:"oth,omitempty"`
}

type cnf struct {
	JWK jose.JSONWebKey `json:"jwk"`
}

type exampleInput struct {
	signer jose.Signer
	rand   io.Reader
	alg    jose.SignatureAlgorithm
}

type exampleOutput struct {
	Alg        jose.SignatureAlgorithm
	WIT        string
	WITClaims  witClaims
	Key        ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func generateWorkloadIdentityToken(claims witClaims, inputOptions []inputOption, outputOptions []outputOption) (exampleOutput, error) {
	input := exampleInput{
		rand: rand.Reader,
		alg:  jose.EdDSA,
	}
	for _, opt := range inputOptions {
		if err := opt(&input); err != nil {
			return exampleOutput{}, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	pubKey, privKey, err := ed25519.GenerateKey(input.rand)
	if err != nil {
		panic("failed to generate wl key")
	}

	claims.Cnf = cnf{
		JWK: jose.JSONWebKey{
			Key:       pubKey,
			Algorithm: string(input.alg),
		},
	}
	cb := jwt.Signed(input.signer).Claims(claims)
	enc, err := cb.Serialize()
	if err != nil {
		return exampleOutput{}, fmt.Errorf("failed to sign WIT: %w", err)
	}

	result := exampleOutput{
		Alg:        input.alg,
		WIT:        enc,
		WITClaims:  claims,
		Key:        pubKey,
		PrivateKey: privKey,
	}
	for _, opt := range outputOptions {
		if err := opt(&result); err != nil {
			return exampleOutput{}, fmt.Errorf("failed to apply option: %w", err)
		}
	}
	return result, nil
}

type inputOption func(input *exampleInput) error

func withRand(rand io.Reader) inputOption {
	return func(input *exampleInput) error {
		input.rand = rand
		return nil
	}
}

func withSigner(signer jose.Signer) inputOption {
	return func(input *exampleInput) error {
		input.signer = signer
		return nil
	}
}

type outputOption func(result *exampleOutput) error

func withHttpMessageSigRequest(req *http.Request, outSignatureInput *string, outSignature *string) outputOption {
	return func(result *exampleOutput) error {
		req.Header["Workload-Identity-Token"] = []string{result.WIT}

		sigConfig := httpsign.NewSignConfig()
		sigConfig.SetTag("wimse-workload-to-workload")
		sigConfig.SetNonce("abcd1111")
		sigConfig.SignAlg(false)
		sigConfig.SetExpires(time.Now().Add(time.Minute).Unix())
		signer, err := httpsign.NewEd25519Signer(result.PrivateKey,
			sigConfig,
			httpsign.Headers("@method", "@request-target", "workload-identity-token"))
		if err != nil {
			return fmt.Errorf("failed to create request signer: %w", err)
		}
		signatureInput, signature, err := httpsign.SignRequest("wimse", *signer, req)
		if err != nil {
			return fmt.Errorf("failed to sign request: %w", err)
		}

		*outSignatureInput = signatureInput
		*outSignature = signature
		return nil
	}
}

func withHttpMessageSigResponse(req *http.Request, resp *http.Response, outSignatureInput *string, outSignature *string) outputOption {
	return func(result *exampleOutput) error {
		resp.Header["Workload-Identity-Token"] = []string{result.WIT}

		sigConfig := httpsign.NewSignConfig()
		sigConfig.SetTag("wimse-workload-to-workload")
		sigConfig.SetNonce("abcd2222")
		sigConfig.SignAlg(false)
		sigConfig.SetExpires(time.Now().Add(time.Minute).Unix())
		sigHeaders := httpsign.Headers("@status", "workload-identity-token", "content-type", "content-digest")
		sigHeaders.AddHeaderExt("@method", false, false, true, false)
		sigHeaders.AddHeaderExt("@request-target", false, false, true, false)
		signer, err := httpsign.NewEd25519Signer(result.PrivateKey, sigConfig, sigHeaders)
		if err != nil {
			return fmt.Errorf("failed to create response signer: %w", err)
		}

		signatureInput, signature, err := httpsign.SignResponse("wimse", *signer, resp, req)
		if err != nil {
			return fmt.Errorf("failed to sign response: %w", err)
		}

		*outSignatureInput = signatureInput
		*outSignature = signature
		return nil
	}
}

type WPTParameters struct {
	Rand             io.Reader
	Audience         string
	AccessToken      string
	TransactionToken string
	OtherTokens      map[string]string
}

func withWorkloadProofToken(params WPTParameters, outWPT *string, outWPTClaims *wptClaims) outputOption {
	return func(result *exampleOutput) error {
		claims := wptClaims{
			Aud:       params.Audience,
			ExpiresAt: now.Add(wptTTL).Unix(),
			Id:        mustGenerateJTI(params.Rand),
		}

		if params.AccessToken != "" {
			claims.Ath = base64UrlEncTokenHash(params.AccessToken)
		}

		if params.TransactionToken != "" {
			claims.Tth = base64UrlEncTokenHash(params.TransactionToken)
		}

		oth := make(map[string]string)
		for k, v := range params.OtherTokens {
			oth[k] = base64UrlEncTokenHash(v)
		}
		claims.Oth = oth

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: result.Alg, Key: result.PrivateKey}, (&jose.SignerOptions{}).WithType(wptJWTType))
		if err != nil {
			return fmt.Errorf("failed to create WPT signer: %w", err)
		}

		enc, err := jwt.Signed(signer).Claims(claims).Serialize()
		if err != nil {
			return fmt.Errorf("failed to sign WPT: %w", err)
		}

		*outWPT = enc
		*outWPTClaims = claims
		return nil
	}
}

func mustGenerateJTI(rand io.Reader) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func base64UrlEncTokenHash(raw string) string {
	if raw == "" {
		return ""
	}

	h := sha256.New()
	h.Write([]byte(raw))

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil))
}
