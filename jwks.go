package keyfunc

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

var (

	// ErrKIDNotFound indicates that the given key ID was not found in the JWKS.
	ErrKIDNotFound = errors.New("the given key ID was not found in the JWKS")

	// ErrMissingAssets indicates there are required assets missing to create a public key.
	ErrMissingAssets = errors.New("required assets are missing to create a public key")
)

// ErrorHandler is a function signature that consumes an error.
type ErrorHandler func(err error)

// JSONKey represents a raw key inside a JWKS.
type JSONKey struct {
	Curve       string `json:"crv"`
	Exponent    string `json:"e"`
	ID          string `json:"kid"`
	Modulus     string `json:"n"`
	X           string `json:"x"`
	Y           string `json:"y"`
	precomputed interface{}
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys                map[string]*JSONKey
	client              *http.Client
	endBackground       chan struct{}
	endOnce             sync.Once
	jwksURL             string
	mux                 sync.RWMutex
	refreshErrorHandler ErrorHandler
	refreshInterval     *time.Duration
	refreshTimeout      *time.Duration
	refreshUnknownKID   bool
}

// rawJWKS represents a JWKS in JSON format.
type rawJWKS struct {
	Keys []JSONKey `json:"keys"`
}

// New creates a new JWKS from a raw JSON message.
func New(jwksBytes json.RawMessage) (jwks *JWKS, err error) {

	// Turn the raw JWKS into the correct Go type.
	var rawKS rawJWKS
	if err = json.Unmarshal(jwksBytes, &rawKS); err != nil {
		return nil, err
	}

	// Iterate through the keys in the raw JWKS. Add them to the JWKS.
	jwks = &JWKS{
		Keys: make(map[string]*JSONKey, len(rawKS.Keys)),
	}
	for _, key := range rawKS.Keys {
		key := key
		jwks.Keys[key.ID] = &key
	}

	return jwks, nil
}

// EndBackground ends the background goroutine to update the JWKs. It can only happen once and is only effective if the
// JWKS has a background goroutine refreshing the JWKS keys.
func (j *JWKS) EndBackground() {
	j.endOnce.Do(func() {
		if j.endBackground != nil {
			close(j.endBackground)
		}
	})
}

// getKey gets the JSONKey from the given KID from the JWKS. It may refresh the JWKS if configured to.
func (j *JWKS) getKey(kid string) (jsonKey *JSONKey, err error) {

	// Get the JSONKey from the JWKS.
	var ok bool
	j.mux.RLock()
	jsonKey, ok = j.Keys[kid]
	j.mux.RUnlock()

	// Check if the key was present.
	if !ok {

		// Check to see if configured to refresh on unknown kid.
		if j.refreshUnknownKID {

			// Refresh the JWKS.
			if err = j.refresh(); err != nil && j.refreshErrorHandler != nil {
				j.refreshErrorHandler(err)
				err = nil
			}

			// Lock the JWKS for async safe use.
			j.mux.RLock()
			defer j.mux.RUnlock()

			// Check if the JWKS refresh contained the requested key.
			if jsonKey, ok = j.Keys[kid]; ok {
				return jsonKey, nil
			}
		}

		return nil, ErrKIDNotFound
	}

	return jsonKey, nil
}
