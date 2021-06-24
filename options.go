package keyfunc

import (
	"net/http"
	"time"
)

// Options represents the configuration options for a JWKs.
type Options struct {

	// Client is the HTTP client used to get the JWKs via HTTP.
	Client *http.Client

	// RefreshInterval is the duration to refresh the JWKs in the background via a new HTTP request. If this is not nil,
	// then a background refresh will be performed in a separate goroutine until the JWKs method EndBackground is
	// called.
	RefreshInterval *time.Duration

	// RefreshTimeout is the duration for the context used to create the HTTP request for a refresh of the JWKs. This
	// defaults to one minute. This is only effectual if RefreshInterval is not nil.
	RefreshTimeout *time.Duration

	// RefreshErrorHandler is a function that consumes errors that happen during a JWKs refresh. This is only effectual
	// if RefreshInterval is not nil.
	RefreshErrorHandler ErrorHandler

	// RefreshUnknownKID indicates that the JWKs should be refreshed via HTTP every time a kid that isn't known is found.
	// On its own, this behavior allows a malicious client to self-sign X JWTs, send them to this service, then cause
	// potentially high network usage proportional to X. Set a RefreshUnknownMinTimespan to mitigate this issue.
	RefreshUnknownKID *bool

	// RefreshUnknownKIDminInterval is the duration that must pass between any two unknown-kid-triggered JWK refreshes.
	// Setting this to a reasonable value helps prevent malicious clients from launching a denial of service attack by
	// sending fake or self-signed JWTs.
	RefreshUnknownKIDMinInterval *time.Duration
}

// applyOptions applies the given options to the given JWKs.
func applyOptions(jwks *JWKs, options Options) {
	if options.Client != nil {
		jwks.client = options.Client
	}
	if options.RefreshErrorHandler != nil {
		jwks.refreshErrorHandler = options.RefreshErrorHandler
	}
	if options.RefreshInterval != nil {
		jwks.refreshInterval = options.RefreshInterval
	}
	if options.RefreshTimeout != nil {
		jwks.refreshTimeout = options.RefreshTimeout
	}
	if options.RefreshUnknownKID != nil {
		jwks.refreshUnknownKID = *options.RefreshUnknownKID
	}
	if options.RefreshUnknownKIDMinInterval != nil {
		jwks.refreshUnknownKIDminInterval = options.RefreshUnknownKIDMinInterval
	}
}
