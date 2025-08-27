package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

var (
	staticRand io.Reader
	now        = time.Date(2025, time.July, 7, 12, 0, 0, 0, time.UTC)
)

func init() {
	// Generate deterministic examples. DEMO ONLY. DO NOT USE.
	staticRand = &deterministicRandomReader{Reader: rand.New(rand.NewSource(42))}
	jose.RandReader = staticRand
}

const (
	witJWTType = "wimse-id+jwt"
	wptJWTType = "wimse-proof+jwt"
	subject    = "wimse://example.com/specific-workload"
	issuer     = "https://example.com"
	audience   = "https://workload.example.com/path"
	witTTL     = time.Hour
	wptTTL     = 5 * time.Minute
	keyID      = "June 5"

	// arbitrary examples
	rawAT           = "16_mAd0GiwaZokU26_0902100"
	rawTxnToken     = "1231231231231231"
	rawSessionToken = "sess_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q"
)

func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), staticRand)
	if err != nil {
		panic(fmt.Errorf("failed to generate key: %w", err))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).
		WithType(witJWTType).
		WithHeader("kid", keyID))
	if err != nil {
		panic(fmt.Errorf("failed to create WIT signer: %w", err))
	}

	signerKey := jose.JSONWebKey{
		KeyID: keyID,
		Key:   &key.PublicKey,
	}
	err = writeIncludesJSON("signer-key.txt", signerKey)
	if err != nil {
		panic(fmt.Errorf("failed to write authority key: %w", err))
	}

	// thin example only with required claims
	err = generateThin(withSigner(signer), withRand(staticRand))
	if err != nil {
		panic(fmt.Errorf("failed to generate thin example: %w", err))
	}

	err = generateFull(withSigner(signer), withRand(staticRand))
	if err != nil {
		panic(fmt.Errorf("failed to generate full example: %w", err))
	}
}

func generateThin(inputOptions ...inputOption) error {
	prefix := "thin-"
	wit := witClaims{
		Subject:   subject,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(witTTL).Unix(),
	}

	outputOptions := []outputOption{
		func(result *exampleOutput) error {
			return writeIncludes(fmt.Sprintf("%swit.txt", prefix), result.WIT)
		},
		func(result *exampleOutput) error {
			witRequest := fmt.Sprintf("Workload-Identity-Token: %s", result.WIT)
			return writeIncludes(fmt.Sprintf("%swit-request.txt", prefix), witRequest)
		},
		func(result *exampleOutput) error {
			return writeIncludesJSON(fmt.Sprintf("%swit-claims.txt", prefix), result.WITClaims)
		},
		func(result *exampleOutput) error {
			return writeIncludesHeaderJSON(fmt.Sprintf("%swit-header.txt", prefix), result.WIT)
		},
		func(result *exampleOutput) error {
			workloadKey := jose.JSONWebKey{
				Key: result.PrivateKey,
			}
			return writeIncludesJSON("workload-key.txt", workloadKey)
		},
	}

	// generate WPT
	outputOptions = append(outputOptions, generateWorkloadProofToken(prefix, WPTParameters{
		Audience: audience,
		Rand:     staticRand,
	})...)

	// generate http message sig
	outputOptions = append(outputOptions, generateHttpMessageSig(prefix)...)

	_, err := generateWorkloadIdentityToken(wit, inputOptions, outputOptions)
	if err != nil {
		return fmt.Errorf("failed to generate example: %w", err)
	}

	return nil
}

func generateFull(inputOptions ...inputOption) error {
	prefix := "full-"
	wit := witClaims{
		Subject:   subject,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(witTTL).Unix(),

		// optional claims
		Id:     mustGenerateJTI(staticRand),
		Issuer: issuer,
	}

	outputOptions := []outputOption{
		func(result *exampleOutput) error {
			return writeIncludes(fmt.Sprintf("%swit.txt", prefix), result.WIT)
		},
		func(result *exampleOutput) error {
			return writeIncludesJSON(fmt.Sprintf("%swit-claims.txt", prefix), result.WITClaims)
		},
	}

	outputOptions = append(outputOptions, generateWorkloadProofToken(prefix, WPTParameters{
		Audience: audience,
		Rand:     staticRand,

		// optional claims
		AccessToken:      rawAT,
		TransactionToken: rawTxnToken,
		OtherTokens: map[string]string{
			"X-Session-Token": rawSessionToken,
		},
	})...)

	_, err := generateWorkloadIdentityToken(wit, inputOptions, outputOptions)
	if err != nil {
		return fmt.Errorf("failed to generate example: %w", err)
	}

	return nil
}

func generateWorkloadProofToken(prefix string, params WPTParameters) []outputOption {
	var wpt string
	var wptClaims wptClaims
	return []outputOption{
		withWorkloadProofToken(params, &wpt, &wptClaims),
		func(result *exampleOutput) error {
			return writeIncludes(fmt.Sprintf("%swpt.txt", prefix), wpt)
		},
		func(result *exampleOutput) error {
			return writeIncludesHeaderJSON(fmt.Sprintf("%swpt-header.txt", prefix), wpt)
		},
		func(result *exampleOutput) error {
			wptRequest := fmt.Sprintf(`POST /path HTTP/1.1
Host: workload.example.com
Content-Type: application/json
Workload-Identity-Token: %s
Workload-Proof-Token: %s

{"do stuff":"please"}`, result.WIT, wpt)
			return writeIncludes(fmt.Sprintf("%swpt-request.txt", prefix), wptRequest)
		},
		func(result *exampleOutput) error {
			return writeIncludesJSON(fmt.Sprintf("%swpt-claims.txt", prefix), wptClaims)
		},
	}
}

func generateHttpMessageSig(prefix string) []outputOption {
	var outputOptions []outputOption

	req := http.Request{
		Method: http.MethodGet,
		Header: http.Header{},
		URL: &url.URL{
			Scheme:   "https",
			Host:     "example.com",
			Path:     "gimme-ice-cream",
			RawQuery: "flavor=vanilla",
		},
	}
	var reqSigInput, reqSig string
	outputOptions = append(outputOptions,
		withHttpMessageSigRequest(&req, &reqSigInput, &reqSig),
		func(result *exampleOutput) error {
			httpSigRequest := fmt.Sprintf(`GET /gimme-ice-cream?flavor=vanilla HTTP/1.1
Host: example.com
Signature: %s
Signature-Input: %s
Workload-Identity-Token: %s
`, reqSig, reqSigInput, result.WIT)
			return writeIncludes(fmt.Sprintf("%ssigs-request.txt", prefix), httpSigRequest)
		},
	)

	responseHeaders := http.Header{}
	responseHeaders.Set("Content-Digest", "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:")
	responseHeaders.Set("Content-Type", "text/plain")
	responseHeaders.Set("Connection", "close")
	resp := http.Response{
		StatusCode: http.StatusNotFound,
		Header:     responseHeaders,
	}
	var respSigInput, respSig string
	outputOptions = append(outputOptions,
		withHttpMessageSigResponse(&req, &resp, &respSigInput, &respSig),
		func(result *exampleOutput) error {
			httpSigResponse := fmt.Sprintf(`HTTP/1.1 404 Not Found
Connection: close
Content-Digest: sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:
Content-Type: text/plain
Signature: %s
Signature-Input: %s
Workload-Identity-Token: %s

No ice cream today.
`, respSig, respSigInput, result.WIT)
			return writeIncludes(fmt.Sprintf("%ssigs-response.txt", prefix), httpSigResponse)
		},
	)

	return outputOptions
}

func writeIncludes(fileName string, content string) error {
	includesPath := filepath.Join("..", "includes", fileName)
	return os.WriteFile(includesPath, []byte(content), 0644)
}

func writeIncludesJSON(fileName string, claims interface{}) error {
	claimsJSON, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		panic(err)
	}
	return writeIncludes(fileName, string(claimsJSON))
}

func writeIncludesHeaderJSON(fileName string, token string) error {
	rawHeader := strings.Split(token, ".")[0]

	decHeader, err := base64.URLEncoding.DecodeString(rawHeader)
	if err != nil {
		return fmt.Errorf("failed to decode header: %w", err)
	}

	var header interface{}
	if err := json.Unmarshal(decHeader, &header); err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}

	prettyJSON, err := json.MarshalIndent(header, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}
	return writeIncludes(fileName, string(prettyJSON))
}

type deterministicRandomReader struct {
	io.Reader
}

func (r *deterministicRandomReader) Read(p []byte) (n int, err error) {
	// hack for crypto/internal/randutil/randutil.go which prevents deterministic key generation
	// DEMO ONLY. DO NOT USE.
	if len(p) == 1 {
		p[0] = 1
		return 1, nil
	}

	return r.Reader.Read(p)
}
