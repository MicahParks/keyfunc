package jwks

import (
	"io/ioutil"
	"net/http"
)

// Get loads the JWKS at the given URL.
func Get(client *http.Client, jwksURL string) (keystore Keystore, err error) {

	// Use the default HTTP client if none was given.
	if client == nil {
		client = http.DefaultClient
	}

	// Get the JWKS as JSON from the given URL.
	var resp *http.Response
	if resp, err = client.Get(jwksURL); err != nil {
		return nil, err
	}
	defer resp.Body.Close() // Ignore any error.

	// Read the raw JWKS from the body of the response.
	var keystoreBytes []byte
	if keystoreBytes, err = ioutil.ReadAll(resp.Body); err != nil {
		return nil, err
	}

	return New(keystoreBytes)
}
