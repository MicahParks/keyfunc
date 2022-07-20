package keyfunc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

var (
	// ErrKIDNotFound indicates that the given key ID was not found in the JWKS.
	ErrKIDNotFound = errors.New("the given key ID was not found in the JWKS")

	// ErrMissingAssets indicates there are required assets are missing to create a public key.
	ErrMissingAssets = errors.New("required assets are missing to create a public key")
)

// ErrorHandler is a function signature that consumes an error.
type ErrorHandler func(err error)

// jsonWebKey represents a raw key inside a JWKS.
type jsonWebKey struct {
	Curve    string `json:"crv"`
	Exponent string `json:"e"`
	K        string `json:"k"`
	ID       string `json:"kid"`
	Modulus  string `json:"n"`
	Type     string `json:"kty"`
	X        string `json:"x"`
	Y        string `json:"y"`
}

// JWKS represents a JSON Web Key Set (JWK Set).
type JWKS struct {
	cancel              context.CancelFunc
	client              *http.Client
	ctx                 context.Context
	raw                 []byte
	givenKeys           map[string]GivenKey
	givenKIDOverride    bool
	jwksURL             string
	keys                map[string]interface{}
	mux                 sync.RWMutex
	refreshErrorHandler ErrorHandler
	refreshInterval     time.Duration
	refreshRateLimit    time.Duration
	refreshRequests     chan context.CancelFunc
	refreshTimeout      time.Duration
	refreshUnknownKID   bool
	requestFactory      func(ctx context.Context, url string) (*http.Request, error)
}

// rawJWKS represents a JWKS in JSON format.
type rawJWKS struct {
	Keys []*jsonWebKey `json:"keys"`
}

// NewJSON creates a new JWKS from a raw JSON message.
func NewJSON(jwksBytes json.RawMessage) (jwks *JWKS, err error) {
	var rawKS rawJWKS
	err = json.Unmarshal(jwksBytes, &rawKS)
	if err != nil {
		return nil, err
	}

	// Iterate through the keys in the raw JWKS. Add them to the JWKS.
	jwks = &JWKS{
		keys: make(map[string]interface{}, len(rawKS.Keys)),
	}
	for _, key := range rawKS.Keys {
		var keyInter interface{}
		switch keyType := key.Type; keyType {
		case ktyEC:
			keyInter, err = key.ECDSA()
			if err != nil {
				continue
			}
		case ktyOKP:
			keyInter, err = key.EdDSA()
			if err != nil {
				continue
			}
		case ktyOct:
			keyInter, err = key.Oct()
			if err != nil {
				continue
			}
		case ktyRSA:
			keyInter, err = key.RSA()
			if err != nil {
				continue
			}
		default:
			// Ignore unknown key types silently.
			continue
		}

		jwks.keys[key.ID] = keyInter
	}

	return jwks, nil
}

// EndBackground ends the background goroutine to update the JWKS. It can only happen once and is only effective if the
// JWKS has a background goroutine refreshing the JWKS keys.
func (j *JWKS) EndBackground() {
	if j.cancel != nil {
		j.cancel()
	}
}

// KIDs returns the key IDs (`kid`) for all keys in the JWKS.
func (j *JWKS) KIDs() (kids []string) {
	j.mux.RLock()
	defer j.mux.RUnlock()
	kids = make([]string, len(j.keys))
	index := 0
	for kid := range j.keys {
		kids[index] = kid
		index++
	}
	return kids
}

// RawJWKS returns a copy of the raw JWKS received from the given JWKS URL.
func (j *JWKS) RawJWKS() []byte {
	j.mux.RLock()
	defer j.mux.RUnlock()
	raw := make([]byte, len(j.raw))
	copy(raw, j.raw)
	return raw
}

// ReadOnlyKeys returns a read-only copy of the mapping of key IDs (`kid`) to cryptographic keys.
func (j *JWKS) ReadOnlyKeys() map[string]interface{} {
	keys := make(map[string]interface{})
	j.mux.Lock()
	for kid, cryptoKey := range j.keys {
		keys[kid] = cryptoKey
	}
	j.mux.Unlock()
	return keys
}

// getKey gets the jsonWebKey from the given KID from the JWKS. It may refresh the JWKS if configured to.
func (j *JWKS) getKey(kid string) (jsonKey interface{}, err error) {
	j.mux.RLock()
	jsonKey, ok := j.keys[kid]
	j.mux.RUnlock()

	if !ok {
		if j.refreshUnknownKID {
			ctx, cancel := context.WithCancel(j.ctx)

			// Refresh the JWKS.
			select {
			case <-j.ctx.Done():
				return
			case j.refreshRequests <- cancel:
			default:
				// If the j.refreshRequests channel is full, return the error early.
				return nil, ErrKIDNotFound
			}

			// Wait for the JWKS refresh to finish.
			<-ctx.Done()

			j.mux.RLock()
			defer j.mux.RUnlock()
			if jsonKey, ok = j.keys[kid]; ok {
				return jsonKey, nil
			}
		}

		return nil, ErrKIDNotFound
	}

	return jsonKey, nil
}
