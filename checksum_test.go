package keyfunc_test

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt/v4"

	"github.com/MicahParks/keyfunc"
)

func TestChecksum(t *testing.T) {

	// Create a temporary directory to serve the JWKS from.
	tempDir, err := ioutil.TempDir("", "*")
	if err != nil {
		t.Errorf("Failed to create a temporary directory.\nError: %s", err.Error())
		t.FailNow()
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Errorf("Failed to remove temporary directory.\nError: %s", err.Error())
			t.FailNow()
		}
	}()

	// Create the JWKS file path.
	jwksFile := filepath.Join(tempDir, jwksFilePath)

	// Write the JWKS.
	err = ioutil.WriteFile(jwksFile, []byte(jwksJSON), 0600)
	if err != nil {
		t.Errorf("Failed to write JWKS file to temporary directory.\nError: %s", err.Error())
		t.FailNow()
	}

	// Create the HTTP test server.
	server := httptest.NewServer(http.FileServer(http.Dir(tempDir)))
	defer server.Close()

	// Create testing options.
	testingRefreshErrorHandler := func(err error) {
		panic(fmt.Sprintf("Unhandled JWKS error: %s", err.Error()))
	}
	opts := keyfunc.Options{
		RefreshErrorHandler: testingRefreshErrorHandler,
		RefreshUnknownKID:   true,
	}

	// Set the JWKS URL.
	jwksURL := server.URL + jwksFilePath

	jwks, err := keyfunc.Get(jwksURL, opts)
	if err != nil {
		t.Errorf("Failed to get JWKS from testing URL.\nError: %s", err.Error())
		t.FailNow()
	}
	defer jwks.EndBackground()

	// Get a map of all interface pointers for the JWKS.
	cryptoKeyPointers := make(map[string]interface{})
	for kid, cryptoKey := range jwks.ReadOnlyKeys() {
		cryptoKeyPointers[kid] = cryptoKey
	}

	// Create a JWT that will not be in the JWKS.
	token := jwt.New(jwt.SigningMethodHS256)
	token.Header["kid"] = "unknown"
	signed, err := token.SignedString([]byte("test"))
	if err != nil {
		t.Errorf("Failed to sign test JWT.\nError: %s", err.Error())
		t.FailNow()
	}

	// Force the JWKS to refresh.
	_, _ = jwt.Parse(signed, jwks.Keyfunc)

	// Confirm the keys in the JWKS have not been refreshed.
	newKeys := jwks.ReadOnlyKeys()
	if len(newKeys) != len(cryptoKeyPointers) {
		t.Errorf("The number of keys should not be different.")
		t.FailNow()
	}
	for kid, cryptoKey := range newKeys {
		if !reflect.DeepEqual(cryptoKeyPointers[kid], cryptoKey) {
			t.Errorf("The JWKS should not have refreshed without a checksum change.")
			t.FailNow()
		}
	}

	// Write a new JWKS to the test file.
	_, _, jwksBytes, _, err := keysAndJWKS()
	if err != nil {
		t.Errorf("Failed to create a test JWKS.\nError: %s", err.Error())
		t.FailNow()
	}

	// Write a different JWKS.
	err = ioutil.WriteFile(jwksFile, jwksBytes, 0600)
	if err != nil {
		t.Errorf("Failed to write JWKS file to temporary directory.\nError: %s", err.Error())
		t.FailNow()
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
		t.Errorf("A different JWKS checksum should have triggered a JWKS refresh.")
		t.FailNow()
	}
}
