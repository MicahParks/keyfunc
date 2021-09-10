package keyfunc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/MicahParks/keyfunc"
)

const (
	// TODO
	givenKID  = "givenKID"
	remoteKID = "remoteKID"
)

// TODO
type pseudoJWKs struct {
	Keys []pseudoJSONKey `json:"keys"`
}

// TODO
type pseudoJSONKey struct {
	KID string   `json:"kid"`
	E   int      `json:"e"`
	N   *big.Int `json:"n"`
}

// TestNewGiven tests that given keys will be added to a JWKs with a remote resource.
func TestNewGiven(t *testing.T) {

	// Create a temporary directory to serve the JWKs from.
	tempDir, err := ioutil.TempDir("", "*")
	if err != nil {
		t.Errorf("Failed to create a temporary directory.\nError: %s", err.Error())
		t.FailNow()
	}
	defer func() {
		if err = os.RemoveAll(tempDir); err != nil {
			t.Errorf("Failed to remove temporary directory.\nError: %s", err.Error())
			t.FailNow()
		}
	}()

	// Create the JWKs file path.
	jwksFile := filepath.Join(tempDir, "example_jwks.json")

	// Write the empty JWKs.
	if err = ioutil.WriteFile(jwksFile, []byte(jwksJSON), 0600); err != nil {
		t.Errorf("Failed to write JWKs file to temporary directory.\nError: %s", err.Error())
		t.FailNow()
	}

	// Create the HTTP test server.
	server := httptest.NewServer(http.FileServer(http.FS(os.DirFS(tempDir))))
	defer server.Close()

	// Create testing options.
	testingRefreshErrorHandler := func(err error) {
		panic(fmt.Sprintf("Unhandled JWKs error: %s", err.Error()))
	}

	// Set the JWKs URL.
	jwksFilePath := "/example_jwks.json"
	jwksURL := server.URL + jwksFilePath

	// Create the given keys.
	givenKeys := make(map[string]keyfunc.GivenKey)

	// Create the test options.
	options := keyfunc.Options{
		GivenKeys:           nil,
		GivenKIDOverride:    nil,
		RefreshErrorHandler: testingRefreshErrorHandler,
	}

	// Get the remote JWKs.
	var jwks *keyfunc.JWKs
	if jwks, err = keyfunc.Get(jwksURL, options); err != nil {
		t.Errorf("Failed to get the JWKs the testing URL.\nError: %s", err.Error())
		t.FailNow()
	}
}

// TestNewGivenOverride
func TestNewGivenOverride(t *testing.T) {

	// Create a temporary directory to serve the JWKs from.
	tempDir, err := ioutil.TempDir("", "*")
	if err != nil {
		t.Errorf("Failed to create a temporary directory.\nError: %s", err.Error())
		t.FailNow()
	}
	defer func() {
		if err = os.RemoveAll(tempDir); err != nil {
			t.Errorf("Failed to remove temporary directory.\nError: %s", err.Error())
			t.FailNow()
		}
	}()

	// Create the JWKs file path.
	jwksFile := filepath.Join(tempDir, "example_jwks.json")

	// Create the keys used for this test.
	givenKeys, givenPrivateKeys, jwksBytes, remotePrivateKeys, err := keysAndJWKs() // TODO

	// Write the JWKs.
	if err = ioutil.WriteFile(jwksFile, []byte(jwksJSON), 0600); err != nil {
		t.Errorf("Failed to write JWKs file to temporary directory.\nError: %s", err.Error())
		t.FailNow()
	}

	// Create the HTTP test server.
	server := httptest.NewServer(http.FileServer(http.FS(os.DirFS(tempDir))))
	defer server.Close()

	// Create testing options.
	testingRefreshErrorHandler := func(err error) {
		panic(fmt.Sprintf("Unhandled JWKs error: %s", err.Error()))
	}

	// Set the JWKs URL.
	jwksFilePath := "/example_jwks.json"
	jwksURL := server.URL + jwksFilePath
	givenKIDOverride := true

	// Create the test options.
	options := keyfunc.Options{
		GivenKeys:           nil,
		GivenKIDOverride:    &givenKIDOverride,
		RefreshErrorHandler: testingRefreshErrorHandler,
	}

	// TODO
}

// givenTestKeys creates two given test keys. One is randomly generated, the other is from the hardcoded JWKs.
func givenTestKeys() {
	// TODO
}

// TODO
func keysAndJWKs() (givenKeys map[string]keyfunc.GivenKey, givenPrivateKeys map[string]*rsa.PrivateKey, jwksBytes []byte, remotePrivateKeys map[string]*rsa.PrivateKey, err error) {

	// Initialize the function's assets.
	const rsaErrMessage = "failed to create RSA key: %w"
	givenKeys = make(map[string]keyfunc.GivenKey)
	givenPrivateKeys = make(map[string]*rsa.PrivateKey)
	remotePrivateKeys = make(map[string]*rsa.PrivateKey)

	// Create a key not in the remote JWKs.
	var key1 *rsa.PrivateKey
	if key1, err = addRSA(givenKeys, givenKID); err != nil {
		return nil, nil, nil, nil, fmt.Errorf(rsaErrMessage, err)
	}
	givenPrivateKeys[givenKID] = key1

	// Create a key to be overwritten by or override the one with the same key ID in the remote JWKs.
	var key2 *rsa.PrivateKey
	if key2, err = addRSA(givenKeys, remoteKID); err != nil {
		return nil, nil, nil, nil, fmt.Errorf(rsaErrMessage, err)
	}
	givenPrivateKeys[remoteKID] = key2

	// Create a key that exists in the remote JWKs.
	var key3 *rsa.PrivateKey
	if key3, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return nil, nil, nil, nil, fmt.Errorf(rsaErrMessage, err)
	}
	remotePrivateKeys[remoteKID] = key3

	// Create a pseudo-JWKs.
	jwks := pseudoJWKs{Keys: []pseudoJSONKey{{
		KID: remoteKID,
		E:   key3.PublicKey.E,
		N:   key3.PublicKey.N,
	}}}

	// Marshal the JWKs to JSON.
	if jwksBytes, err = json.Marshal(jwks); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to marshal the JWKs to JSON: %w", err)
	}

	return givenKeys, givenPrivateKeys, jwksBytes, remotePrivateKeys, nil
}
