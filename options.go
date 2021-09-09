package keyfunc

import (
	"context"
	"net/http"
	"time"
)

// Options represents the configuration options for a JWKs.
type Options struct {

	// Client is the HTTP client used to get the JWKs via HTTP.
	Client *http.Client

	// Ctx is the context for the keyfunc's background refresh. When the context expires or is canceled, the background
	// goroutine will end.
	Ctx context.Context

	// GivenKeys is a map of JWT key IDs, `kid`, to their given keys. If the JWKs is set to refresh in the background,
	// these values persist across JWKs refreshes, but will be overwritten if the remote JWKs resource contains a key
	// with the same `kid`.
	GivenKeys map[string]GivenKey

	// RefreshErrorHandler is a function that consumes errors that happen during a JWKs refresh. This is only effectual
	// if RefreshInterval is not nil.
	RefreshErrorHandler ErrorHandler

	// RefreshInterval is the duration to refresh the JWKs in the background via a new HTTP request. If this is not nil,
	// then a background refresh will be requested in a separate goroutine at this interval until the JWKs method
	// EndBackground is called.
	RefreshInterval *time.Duration

	// RefreshRateLimit limits the rate at which refresh requests are granted. Only one refresh request can be queued
	// at a time any refresh requests received while there is already a queue are ignored. It does not make sense to
	// have RefreshInterval's value shorter than this.
	RefreshRateLimit *time.Duration

	// RefreshTimeout is the duration for the context used to create the HTTP request for a refresh of the JWKs. This
	// defaults to one minute. This is only effectual if RefreshInterval is not nil.
	RefreshTimeout *time.Duration

	// RefreshUnknownKID indicates that the JWKs refresh request will occur every time a kid that isn't cached is seen.
	// Without specifying a RefreshInterval a malicious client could self-sign X JWTs, send them to this service,
	// then cause potentially high network usage proportional to X.
	RefreshUnknownKID *bool
}

// applyOptions applies the given options to the given JWKs.
func applyOptions(jwks *JWKs, options Options) {
	if options.Client != nil {
		jwks.client = options.Client
	}
	if options.Ctx != nil {
		jwks.ctx, jwks.cancel = context.WithCancel(options.Ctx)
	}
	if options.GivenKeys != nil {
		if jwks.givenKeys == nil {
			jwks.givenKeys = make(map[string]GivenKey)
		}
		for kid, key := range options.GivenKeys {
			jwks.givenKeys[kid] = key
		}
	}
	if options.RefreshErrorHandler != nil {
		jwks.refreshErrorHandler = options.RefreshErrorHandler
	}
	if options.RefreshInterval != nil {
		jwks.refreshInterval = options.RefreshInterval
	}
	if options.RefreshRateLimit != nil {
		jwks.refreshRateLimit = options.RefreshRateLimit
	}
	if options.RefreshTimeout != nil {
		jwks.refreshTimeout = options.RefreshTimeout
	}
	if options.RefreshUnknownKID != nil {
		jwks.refreshUnknownKID = *options.RefreshUnknownKID
	}
}
