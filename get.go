package keyfunc

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

var (

	// defaultRefreshTimeout is the default duration for the context used to create the HTTP request for a refresh of
	// the JWKS.
	defaultRefreshTimeout = time.Minute
)

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Get loads the JWKS at the given URL.
func Get(jwksURL string, options Options) (jwks *JWKS, err error) {

	// Create the JWKS.
	jwks = &JWKS{
		jwksURL: jwksURL,
	}

	// Apply the options to the JWKS.
	applyOptions(jwks, options)

	// Apply some defaults if options were not provided.
	if jwks.client == nil {
		jwks.client = http.DefaultClient
	}
	if jwks.refreshTimeout == 0 {
		jwks.refreshTimeout = defaultRefreshTimeout
	}

	// Get the keys for the JWKS.
	if err = jwks.refresh(); err != nil {
		return nil, err
	}

	// Check to see if a background refresh of the JWKS should happen.
	if jwks.refreshInterval != 0 || jwks.refreshUnknownKID {

		// Attach a context used to end the background goroutine.
		jwks.ctx, jwks.cancel = context.WithCancel(context.Background())

		// Create a channel that will accept requests to refresh the JWKS.
		jwks.refreshRequests = make(chan context.CancelFunc, 1)

		// Start the background goroutine for data refresh.
		go jwks.backgroundRefresh()
	}

	return jwks, nil
}

// backgroundRefresh is meant to be a separate goroutine that will update the keys in a JWKS over a given interval of
// time.
func (j *JWKS) backgroundRefresh() {

	// Create some rate limiting assets.
	var lastRefresh time.Time
	var queueOnce sync.Once
	var refreshMux sync.Mutex
	if j.refreshRateLimit != 0 {
		lastRefresh = time.Now().Add(-j.refreshRateLimit)
	}

	// Create a channel that will never send anything unless there is a refresh interval.
	refreshInterval := make(<-chan time.Time)

	// Enter an infinite loop that ends when the background ends.
	for {

		// If there is a refresh interval, create the channel for it.
		if j.refreshInterval != 0 {
			refreshInterval = time.After(j.refreshInterval)
		}

		// Wait for a refresh to occur or the background to end.
		select {

		// Send a refresh request the JWKS after the given interval.
		case <-refreshInterval:
			select {
			case <-j.ctx.Done():
				return
			case j.refreshRequests <- func() {}:
			default: // If the j.refreshRequests channel is full, don't send another request.
			}

		// Accept refresh requests.
		case cancel := <-j.refreshRequests:

			// Rate limit, if needed.
			refreshMux.Lock()
			if j.refreshRateLimit != 0 && lastRefresh.Add(j.refreshRateLimit).After(time.Now()) {

				// Don't make the JWT parsing goroutine wait for the JWKS to refresh.
				cancel()

				// Only queue a refresh once.
				queueOnce.Do(func() {

					// Launch a goroutine that will get a reservation for a JWKS refresh or fail to and immediately return.
					go func() {

						// Wait for the next time to refresh.
						refreshMux.Lock()
						wait := time.Until(lastRefresh.Add(j.refreshRateLimit))
						refreshMux.Unlock()
						select {
						case <-j.ctx.Done():
							return
						case <-time.After(wait):
						}

						// Refresh the JWKS.
						refreshMux.Lock()
						defer refreshMux.Unlock()
						if err := j.refresh(); err != nil && j.refreshErrorHandler != nil {
							j.refreshErrorHandler(err)
						}

						// Reset the last time for the refresh to now.
						lastRefresh = time.Now()

						// Allow another queue.
						queueOnce = sync.Once{}
					}()
				})
			} else {

				// Refresh the JWKS.
				if err := j.refresh(); err != nil && j.refreshErrorHandler != nil {
					j.refreshErrorHandler(err)
				}

				// Reset the last time for the refresh to now.
				lastRefresh = time.Now()

				// Allow the JWT parsing goroutine to continue with the refreshed JWKS.
				cancel()
			}
			refreshMux.Unlock()

		// Clean up this goroutine when its context expires.
		case <-j.ctx.Done():
			return
		}
	}
}

// refresh does an HTTP GET on the JWKS URL to rebuild the JWKS.
func (j *JWKS) refresh() (err error) {

	// Create a context for the request.
	var ctx context.Context
	var cancel context.CancelFunc
	if j.ctx != nil {
		ctx, cancel = context.WithTimeout(j.ctx, j.refreshTimeout)
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), j.refreshTimeout)
	}
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

	// Only reprocess if the JWKS has changed.
	if len(jwksBytes) != 0 && bytes.Equal(jwksBytes, j.raw) {
		return nil
	}
	j.raw = jwksBytes

	// Create an updated JWKS.
	var updated *JWKS
	if updated, err = NewJSON(jwksBytes); err != nil {
		return err
	}

	// Lock the JWKS for async safe usage.
	j.mux.Lock()
	defer j.mux.Unlock()

	// Update the keys.
	j.keys = updated.keys

	// If given keys were provided, add them back into the refreshed JWKS.
	var ok bool
	if j.givenKeys != nil {
		for kid, key := range j.givenKeys {

			// Only overwrite the key if configured to do so.
			if !j.givenKIDOverride {
				if _, ok = j.keys[kid]; ok {
					continue
				}
			}

			// Write the given key to the JWKS.
			j.keys[kid] = key.inter
		}
	}

	return nil
}
