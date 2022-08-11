package keyfunc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v4"

	"github.com/MicahParks/keyfunc"
)

const (
	givenKID  = "givenKID"
	remoteKID = "remoteKID"
)

// pseudoJWKS is a data structure used to JSON marshal a JWKS but is not fully featured.
type pseudoJWKS struct {
	Keys []pseudoJSONKey `json:"keys"`
}

// pseudoJSONKey is a data structure that is used to JSON marshal a JWK that is not fully featured.
type pseudoJSONKey struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	E   string `json:"e"`
	N   string `json:"n"`
}

// TestNewGiven tests that given keys will be added to a JWKS with a remote resource.
func TestNewGiven(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "*")
	if err != nil {
		t.Fatalf(logFmt, "Failed to create a temporary directory.", err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Fatalf(logFmt, "Failed to remove temporary directory.", err)
		}
	}()

	jwksFile := filepath.Join(tempDir, jwksFilePath)

	givenKeys, givenPrivateKeys, jwksBytes, remotePrivateKeys, err := keysAndJWKS()
	if err != nil {
		t.Fatalf(logFmt, "Failed to create cryptographic keys for the test.", err)
	}

	err = os.WriteFile(jwksFile, jwksBytes, 0600)
	if err != nil {
		t.Fatalf(logFmt, "Failed to write JWKS file to temporary directory.", err)
	}

	server := httptest.NewServer(http.FileServer(http.Dir(tempDir)))
	defer server.Close()

	testingRefreshErrorHandler := func(err error) {
		panic(fmt.Sprintf(logFmt, "Unhandled JWKS error.", err))
	}

	jwksURL := server.URL + jwksFilePath

	options := keyfunc.Options{
		GivenKeys:           givenKeys,
		RefreshErrorHandler: testingRefreshErrorHandler,
	}

	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		t.Fatalf(logFmt, "Failed to get the JWKS the testing URL.", err)
	}

	// Test the given key with a unique key ID.
	createSignParseValidate(t, givenPrivateKeys, jwks, givenKID, true)

	// Test the given key with a non-unique key ID that should be overwritten.
	createSignParseValidate(t, givenPrivateKeys, jwks, remoteKID, false)

	// Test the remote key that should not have been overwritten.
	createSignParseValidate(t, remotePrivateKeys, jwks, remoteKID, true)

	// Change the JWKS options to overwrite remote keys.
	options.GivenKIDOverride = true
	jwks, err = keyfunc.Get(jwksURL, options)
	if err != nil {
		t.Fatalf(logFmt, "Failed to recreate JWKS.", err)
	}

	// Test the given key with a unique key ID.
	createSignParseValidate(t, givenPrivateKeys, jwks, givenKID, true)

	// Test the given key with a non-unique key ID that should overwrite the remote key.
	createSignParseValidate(t, givenPrivateKeys, jwks, remoteKID, true)

	// Test the remote key that should have been overwritten.
	createSignParseValidate(t, remotePrivateKeys, jwks, remoteKID, false)
}

// createSignParseValidate creates, signs, parses, and validates a JWT.
func createSignParseValidate(t *testing.T, keys map[string]*rsa.PrivateKey, jwks *keyfunc.JWKS, kid string, shouldValidate bool) {
	unsignedToken := jwt.New(jwt.SigningMethodRS256)
	unsignedToken.Header[kidAttribute] = kid

	jwtB64, err := unsignedToken.SignedString(keys[kid])
	if err != nil {
		t.Fatalf(logFmt, "Failed to sign the JWT.", err)
	}

	token, err := jwt.Parse(jwtB64, jwks.Keyfunc)
	if err != nil {
		if !shouldValidate && errors.Is(err, rsa.ErrVerification) {
			return
		}
		t.Fatalf(logFmt, "Failed to parse the JWT.", err)
	}

	if !shouldValidate {
		t.Fatalf("The token should not have parsed properly.")
	}

	if !token.Valid {
		t.Fatalf("The JWT is not valid.")
	}
}

// keysAndJWKS creates a couple of cryptographic keys and the remote JWKS associated with them.
func keysAndJWKS() (givenKeys map[string]keyfunc.GivenKey, givenPrivateKeys map[string]*rsa.PrivateKey, jwksBytes []byte, remotePrivateKeys map[string]*rsa.PrivateKey, err error) {
	const rsaErrMessage = "failed to create RSA key: %w"
	givenKeys = make(map[string]keyfunc.GivenKey)
	givenPrivateKeys = make(map[string]*rsa.PrivateKey)
	remotePrivateKeys = make(map[string]*rsa.PrivateKey)

	// Create a key not in the remote JWKS.
	key1, err := addRSA(givenKeys, givenKID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf(rsaErrMessage, err)
	}
	givenPrivateKeys[givenKID] = key1

	// Create a key to be overwritten by or override the one with the same key ID in the remote JWKS.
	key2, err := addRSA(givenKeys, remoteKID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf(rsaErrMessage, err)
	}
	givenPrivateKeys[remoteKID] = key2

	// Create a key that exists in the remote JWKS.
	key3, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf(rsaErrMessage, err)
	}
	remotePrivateKeys[remoteKID] = key3

	jwks := pseudoJWKS{Keys: []pseudoJSONKey{{
		KID: remoteKID,
		KTY: "RSA",
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key3.PublicKey.E)).Bytes()),
		N:   base64.RawURLEncoding.EncodeToString(key3.PublicKey.N.Bytes()),
	}}}

	jwksBytes, err = json.Marshal(jwks)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to marshal the JWKS to JSON: %w", err)
	}

	return givenKeys, givenPrivateKeys, jwksBytes, remotePrivateKeys, nil
}
