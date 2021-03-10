package keyfunc

import (
	"crypto/ecdsa"
	"crypto/rsa"
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
	mux                 sync.RWMutex
	refreshErrorHandler ErrorHandler
	refreshInterval     *time.Duration
	refreshTimeout      *time.Duration
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

// ECDSA retrieves an ECDSA public key from the JWKS.
func (j *JWKS) ECDSA(kid string) (publicKey *ecdsa.PublicKey, err error) {

	// Lock the JWKS for async safe usage.
	j.mux.RLock()
	defer j.mux.RUnlock()

	// Get the JSONKey from the JWKS.
	key, ok := j.Keys[kid]
	if !ok {
		return nil, ErrKIDNotFound
	}

	// Transform the key from JSON to an ECDSA key.
	return key.ECDSA()
}

// RSA retrieves an RSA public key from the JWKS.
func (j *JWKS) RSA(kid string) (publicKey *rsa.PublicKey, err error) {

	// Lock the JWKS for async safe usage.
	j.mux.RLock()
	defer j.mux.RUnlock()

	// Get the JSONKey from the JWKS.
	key, ok := j.Keys[kid]
	if !ok {
		return nil, ErrKIDNotFound
	}

	// Transform the key from JSON to an RSA key.
	return key.RSA()
}
