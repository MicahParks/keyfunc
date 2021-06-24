package keyfunc

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"time"
)

var (

	// defaultRefreshTimeout is the default duration for the context used to create the HTTP request for a refresh of
	// the JWKs.
	defaultRefreshTimeout = time.Minute
)

// Get loads the JWKs at the given URL.
func Get(jwksURL string, options ...Options) (jwks *JWKs, err error) {

	// Create the JWKs.
	jwks = &JWKs{
		jwksURL: jwksURL,
	}

	// Apply the options to the JWKs.
	for _, opts := range options {
		applyOptions(jwks, opts)
	}

	// Apply some defaults if options were not provided.
	if jwks.client == nil {
		jwks.client = http.DefaultClient
	}
	if jwks.refreshTimeout == nil {
		jwks.refreshTimeout = &defaultRefreshTimeout
	}

	// Get the keys for the JWKs.
	if err = jwks.refresh(); err != nil {
		return nil, err
	}

	// Check to see if a background refresh of the JWKs should happen.
	if jwks.refreshInterval != nil {

		// Attach a channel to end the background goroutine.
		jwks.endBackground = make(chan struct{})

		// Start the background goroutine for data refresh.
		go jwks.backgroundRefresh()
	}

	return jwks, nil
}

// backgroundRefresh is meant to be a separate goroutine that will update the keys in a JWKs over a given interval of
// time.
func (j *JWKs) backgroundRefresh() {
	for {
		select {

		// Refresh the JWKs after the given interval.
		case <-time.After(*j.refreshInterval):
			err := j.refresh()

			// Handle an error, if any.
			if err != nil && j.refreshErrorHandler != nil {
				j.refreshErrorHandler(err)
			}

		// Clean up this goroutine.
		case <-j.endBackground:
			return
		}
	}
}

// refresh does an HTTP GET on the JWKs URL to rebuild the JWKs.
func (j *JWKs) refresh() (err error) {

	// Create a context for the request.
	ctx, cancel := context.WithTimeout(context.Background(), *j.refreshTimeout)
	defer cancel()

	// Create the HTTP request.
	var req *http.Request
	if req, err = http.NewRequestWithContext(ctx, http.MethodGet, j.jwksURL, bytes.NewReader(nil)); err != nil {
		return err
	}

	// Get the JWKs as JSON from the given URL.
	var resp *http.Response
	if resp, err = j.client.Do(req); err != nil {
		return err
	}
	defer resp.Body.Close() // Ignore any error.

	// Read the raw JWKs from the body of the response.
	var jwksBytes []byte
	if jwksBytes, err = ioutil.ReadAll(resp.Body); err != nil {
		return err
	}

	// Create an updated JWKs.
	var updated *JWKs
	if updated, err = New(jwksBytes); err != nil {
		return err
	}

	// Lock the JWKs for async safe usage.
	j.keysMux.Lock()
	defer j.keysMux.Unlock()

	// Update the keys.
	j.Keys = updated.Keys

	return nil
}
