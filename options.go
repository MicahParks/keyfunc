package keyfunc

import (
	"context"
	"net/http"
	"time"
)

// Options represents the configuration options for a JWKS.
//
// If RefreshInterval and or RefreshUnknownKID is not nil, then a background goroutine will be launched to refresh the
// remote JWKS under the specified circumstances.
//
// When using a background refresh goroutine, make sure to use RefreshRateLimit if paired with RefreshUnknownKID. Also
// make sure to end the background refresh goroutine with the JWKS.EndBackground method when it's no longer needed.
type Options struct {
	// Client is the HTTP client used to get the JWKS via HTTP.
	Client *http.Client

	// Ctx is the context for the keyfunc's background refresh. When the context expires or is canceled, the background
	// goroutine will end.
	Ctx context.Context

	// GivenKeys is a map of JWT key IDs, `kid`, to their given keys. If the JWKS has a background refresh goroutine,
	// these values persist across JWKS refreshes. By default, if the remote JWKS resource contains a key with the same
	// `kid` any given keys with the same `kid` will be overwritten by the keys from the remote JWKS. Use the
	// GivenKIDOverride option to flip this behavior.
	GivenKeys map[string]GivenKey

	// GivenKIDOverride will make a GivenKey override any keys with the same ID (`kid`) in the remote JWKS. The is only
	// effectual if GivenKeys is provided.
	GivenKIDOverride bool

	// RefreshErrorHandler is a function that consumes errors that happen during a JWKS refresh. This is only effectual
	// if a background refresh goroutine is active.
	RefreshErrorHandler ErrorHandler

	// RefreshInterval is the duration to refresh the JWKS in the background via a new HTTP request. If this is not nil,
	// then a background goroutine will be used to refresh the JWKS once per the given interval. Make sure to call the
	// JWKS.EndBackground method to end this goroutine when it's no longer needed.
	RefreshInterval time.Duration

	// RefreshRateLimit limits the rate at which refresh requests are granted. Only one refresh request can be queued
	// at a time any refresh requests received while there is already a queue are ignored. It does not make sense to
	// have RefreshInterval's value shorter than this.
	RefreshRateLimit time.Duration

	// RefreshTimeout is the duration for the context timeout used to create the HTTP request for a refresh of the JWKS.
	// This defaults to one minute. This is used for the HTTP request and any background goroutine refreshes.
	RefreshTimeout time.Duration

	// RefreshUnknownKID indicates that the JWKS refresh request will occur every time a kid that isn't cached is seen.
	// This is done through a background goroutine. Without specifying a RefreshInterval a malicious client could
	// self-sign X JWTs, send them to this service, then cause potentially high network usage proportional to X. Make
	// sure to call the JWKS.EndBackground method to end this goroutine when it's no longer needed.
	RefreshUnknownKID bool

	// RequestFactory creates HTTP requests for the remote JWKS resource located at the given url. For example, an
	// HTTP header could be added to indicate a User-Agent.
	RequestFactory func(ctx context.Context, url string) (*http.Request, error)
}

// applyOptions applies the given options to the given JWKS.
func applyOptions(jwks *JWKS, options Options) {
	if options.Ctx != nil {
		jwks.ctx, jwks.cancel = context.WithCancel(options.Ctx)
	}

	if options.GivenKeys != nil {
		jwks.givenKeys = make(map[string]GivenKey)
		for kid, key := range options.GivenKeys {
			jwks.givenKeys[kid] = key
		}
	}

	jwks.client = options.Client
	jwks.givenKIDOverride = options.GivenKIDOverride
	jwks.refreshErrorHandler = options.RefreshErrorHandler
	jwks.refreshInterval = options.RefreshInterval
	jwks.refreshRateLimit = options.RefreshRateLimit
	jwks.refreshTimeout = options.RefreshTimeout
	jwks.refreshUnknownKID = options.RefreshUnknownKID
	jwks.requestFactory = options.RequestFactory
}
