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

	// ErrJWKUse indicated that the given key was found in the JWKS, but was explicitly not authorized for signature verification.
	ErrJWKUse = errors.New("the given key ID is not authorized for signature verification")
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
	Use      string `json:"use"`
	X        string `json:"x"`
	Y        string `json:"y"`
}

// parsedKey represents a parsed JWK with assoicated metadata
type parsedKey struct {
	use    string
	public interface{}
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
	keys                map[string]parsedKey
	mux                 sync.RWMutex
	refreshErrorHandler ErrorHandler
	refreshInterval     time.Duration
	refreshRateLimit    time.Duration
	refreshRequests     chan context.CancelFunc
	refreshTimeout      time.Duration
	refreshUnknownKID   bool
	requestFactory      func(ctx context.Context, url string) (*http.Request, error)
	responseExtractor   func(ctx context.Context, resp *http.Response) (json.RawMessage, error)
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
		keys: make(map[string]parsedKey, len(rawKS.Keys)),
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

		jwks.keys[key.ID] = parsedKey{
			use:    key.Use,
			public: keyInter,
		}
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

// Len returns the number of keys in the JWKS.
func (j *JWKS) Len() int {
	j.mux.RLock()
	defer j.mux.RUnlock()
	return len(j.keys)
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
	const useEncryption = "enc"

	j.mux.RLock()
	parsedKey, ok := j.keys[kid]
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
			if parsedKey, ok = j.keys[kid]; ok {

				if parsedKey.use == useEncryption {
					return nil, ErrJWKUse
				}

				return parsedKey.public, nil
			}
		}

		return nil, ErrKIDNotFound
	}

	if parsedKey.use == useEncryption {
		return nil, ErrJWKUse
	}

	return parsedKey.public, nil
}
