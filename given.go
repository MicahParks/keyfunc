package keyfunc

import (
	"crypto/ecdsa"
	"crypto/rsa"
)

// GivenKey represents a cryptographic key that resides in a JWKS. In conjuncture with Options.
type GivenKey struct {
	inter interface{}
}

// NewGiven creates a JWKS from a map of given keys.
func NewGiven(givenKeys map[string]GivenKey) (jwks *JWKS) {

	// Initialize the map of kid to cryptographic keys.
	keys := make(map[string]interface{})

	// Copy the given keys to the map of cryptographic keys.
	for kid, given := range givenKeys {
		keys[kid] = given.inter
	}

	// Return a JWKS with the map of cryptographic keys.
	return &JWKS{
		keys: keys,
	}
}

// NewGivenCustom creates a new GivenKey given an untyped variable. The key argument is expected to be a supported
// by the jwt package used.
//
// See the https://pkg.go.dev/github.com/golang-jwt/jwt/v4#RegisterSigningMethod function for registering an unsupported
// signing method.
func NewGivenCustom(key interface{}) (givenKey GivenKey) {
	return GivenKey{
		inter: key,
	}
}

// NewGivenECDSA creates a new GivenKey given an ECDSA public key.
func NewGivenECDSA(key *ecdsa.PublicKey) (givenKey GivenKey) {
	return GivenKey{
		inter: key,
	}
}

// NewGivenHMAC creates a new GivenKey given an HMAC key in a byte slice.
func NewGivenHMAC(key []byte) (givenKey GivenKey) {
	return GivenKey{
		inter: key,
	}
}

// NewGivenRSA creates a new GivenKey given an RSA public key.
func NewGivenRSA(key *rsa.PublicKey) (givenKey GivenKey) {
	return GivenKey{
		inter: key,
	}
}
