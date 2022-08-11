package keyfunc_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt/v4"

	"github.com/MicahParks/keyfunc"
)

// TestChecksum confirms that the JWKS will only perform a refresh if a new JWKS is read from the remote resource.
func TestChecksum(t *testing.T) {
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

	err = os.WriteFile(jwksFile, []byte(jwksJSON), 0600)
	if err != nil {
		t.Fatalf(logFmt, "Failed to write JWKS file to temporary directory.", err)
	}

	server := httptest.NewServer(http.FileServer(http.Dir(tempDir)))
	defer server.Close()

	testingRefreshErrorHandler := func(err error) {
		panic(fmt.Sprintf(logFmt, "Unhandled JWKS error.", err))
	}
	opts := keyfunc.Options{
		RefreshErrorHandler: testingRefreshErrorHandler,
		RefreshUnknownKID:   true,
	}

	jwksURL := server.URL + jwksFilePath

	jwks, err := keyfunc.Get(jwksURL, opts)
	if err != nil {
		t.Fatalf(logFmt, "Failed to get JWKS from testing URL.", err)
	}
	defer jwks.EndBackground()

	cryptoKeyPointers := make(map[string]interface{})
	for kid, cryptoKey := range jwks.ReadOnlyKeys() {
		cryptoKeyPointers[kid] = cryptoKey
	}

	// Create a JWT that will not be in the JWKS.
	token := jwt.New(jwt.SigningMethodHS256)
	token.Header["kid"] = "unknown"
	signed, err := token.SignedString([]byte("test"))
	if err != nil {
		t.Fatalf(logFmt, "Failed to sign test JWT.", err)
	}

	// Force the JWKS to refresh.
	_, _ = jwt.Parse(signed, jwks.Keyfunc)

	// Confirm the keys in the JWKS have not been refreshed.
	newKeys := jwks.ReadOnlyKeys()
	if len(newKeys) != len(cryptoKeyPointers) {
		t.Fatalf("The number of keys should not be different.")
	}
	for kid, cryptoKey := range newKeys {
		if !reflect.DeepEqual(cryptoKeyPointers[kid], cryptoKey) {
			t.Fatalf("The JWKS should not have refreshed without a checksum change.")
		}
	}

	// Write a different JWKS.
	_, _, jwksBytes, _, err := keysAndJWKS()
	if err != nil {
		t.Fatalf(logFmt, "Failed to create a test JWKS.", err)
	}
	err = os.WriteFile(jwksFile, jwksBytes, 0600)
	if err != nil {
		t.Fatalf(logFmt, "Failed to write JWKS file to temporary directory.", err)
	}

	// Force the JWKS to refresh.
	_, _ = jwt.Parse(signed, jwks.Keyfunc)

	// Confirm the keys in the JWKS have been refreshed.
	newKeys = jwks.ReadOnlyKeys()
	different := false
	for kid, cryptoKey := range newKeys {
		if !reflect.DeepEqual(cryptoKeyPointers[kid], cryptoKey) {
			different = true
			break
		}
	}
	if !different {
		t.Fatalf("A different JWKS checksum should have triggered a JWKS refresh.")
	}
}
