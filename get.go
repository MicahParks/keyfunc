package jwks

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
)

// Get loads the JWKS at the given URL.
func Get(ctx context.Context, client *http.Client, jwksURL string) (keystore Keystore, err error) {

	// Use the default HTTP client if none was given.
	if client == nil {
		client = http.DefaultClient
	}

	// Create the HTTP request.
	var req *http.Request
	if req, err = http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, bytes.NewReader(nil)); err != nil {
		return nil, err
	}

	// Get the JWKS as JSON from the given URL.
	var resp *http.Response
	if resp, err = client.Do(req); err != nil {
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
