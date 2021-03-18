package keyfunc

import (
	"net/http"
	"time"
)

// Options represents the configuration options for a JWKS.
type Options struct {

	// Client is the HTTP client used to get the JWKS via HTTP.
	Client *http.Client

	// RefreshInterval is the duration to refresh the JWKS in the background via a new HTTP request. If this is not nil,
	// then a background refresh will be performed in a separate goroutine until the JWKS method EndBackground is
	// called.
	RefreshInterval *time.Duration

	// RefreshTimeout is the duration for the context used to create the HTTP request for a refresh of the JWKS. This
	// defaults to one minute. This is only effectual if RefreshInterval is not nil.
	RefreshTimeout *time.Duration

	// RefreshErrorHandler is a function that consumes errors that happen during a JWKS refresh. This is only effectual
	// if RefreshInterval is not nil.
	RefreshErrorHandler ErrorHandler

	// RefreshUnknownKID indicates that the JWKS should be refreshed via HTTP every time a kid that isn't know is found.
	// This means the
	RefreshUnknownKID *bool
}

// applyOptions applies the given options to the given JWKS.
func applyOptions(jwks *JWKS, options Options) {
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
}
