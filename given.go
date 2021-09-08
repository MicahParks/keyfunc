package keyfunc

import (
	"crypto/ecdsa"
	"crypto/rsa"
)

// GivenKey represents a cryptographic key that resides in a JWKs. In conjuncture with Options.
type GivenKey struct {
	precomputed interface{}
}

// NewGiven creates a JWKs from a map of given keys.
func NewGiven(givenKeys map[string]GivenKey) (jwks *JWKs) {

	// Initialize the map of kid to cryptographic keys.
	keys := make(map[string]*JSONKey)

	// Copy the given keys to the map of cryptographic keys.
	for kid, given := range givenKeys {
		keys[kid] = &JSONKey{
			precomputed: given.precomputed,
		}
	}

	// Return a JWKs with the map of cryptographic keys.
	return &JWKs{
		Keys: keys,
	}
}

// NewGivenKeyCustom creates a new GivenKey given an untyped variable. The key argument is expected to be a supported
// by the jwt package used.
//
// See the https://pkg.go.dev/github.com/golang-jwt/jwt/v4#RegisterSigningMethod function for registering an unsupported
// signing method.
func NewGivenKeyCustom(key interface{}) (givenKey GivenKey) {
	return GivenKey{
		precomputed: key,
	}
}

// NewGivenECDSA creates a new GivenKey given an ECDSA public key.
func NewGivenECDSA(key *ecdsa.PublicKey) (givenKey GivenKey) {
	return GivenKey{
		precomputed: key,
	}
}

// NewGivenKeyHMAC creates a new GivenKey given an HMAC key in a byte slice.
func NewGivenKeyHMAC(key []byte) (givenKey GivenKey) {
	return GivenKey{
		precomputed: key,
	}
}

// NewGivenKeyRSA creates a new GivenKey given an RSA public key.
func NewGivenKeyRSA(key *rsa.PublicKey) (givenKey GivenKey) {
	return GivenKey{
		precomputed: key,
	}
}
