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
	// the JWKS.
	defaultRefreshTimeout = time.Minute
)

// Get loads the JWKS at the given URL.
func Get(jwksURL string, options ...Options) (jwks *JWKS, err error) {

	// Create the JWKS.
	jwks = &JWKS{
		jwksURL: jwksURL,
	}

	// Apply the options to the JWKS.
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

	// Check to see if a background refresh of the JWKS should happen.
	if jwks.refreshInterval != nil {

		// Attach a channel to end the background goroutine.
		jwks.endBackground = make(chan struct{})

		// Start the background goroutine when this function returns.
		defer func() {
			go jwks.backgroundRefresh()
		}()
	}

	// Get the keys for the JWKS.
	if err = jwks.refresh(); err != nil {
		return nil, err
	}

	return jwks, nil
}

// backgroundRefresh is meant to be a separate goroutine that will update the keys in a JWKS over a given interval of
// time.
func (j *JWKS) backgroundRefresh() {
	for {
		select {

		// Refresh the JWKS after the given interval.
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

// refresh does an HTTP GET on the JWKS URL to rebuild the JWKS.
func (j *JWKS) refresh() (err error) {

	// Create a context for the request.
	ctx, cancel := context.WithTimeout(context.Background(), *j.refreshTimeout)
	defer cancel()

	// Create the HTTP request.
	var req *http.Request
	if req, err = http.NewRequestWithContext(ctx, http.MethodGet, j.jwksURL, bytes.NewReader(nil)); err != nil {
		return err
	}

	// Get the JWKS as JSON from the given URL.
	var resp *http.Response
	if resp, err = j.client.Do(req); err != nil {
		return err
	}
	defer resp.Body.Close() // Ignore any error.

	// Read the raw JWKS from the body of the response.
	var jwksBytes []byte
	if jwksBytes, err = ioutil.ReadAll(resp.Body); err != nil {
		return err
	}

	// Create an updated JWKS.
	var updated *JWKS
	if updated, err = New(jwksBytes); err != nil {
		return err
	}

	// Lock the JWKS for async safe usage.
	j.mux.Lock()
	defer j.mux.Unlock()

	// Update the keys.
	j.Keys = updated.Keys

	return nil
}
