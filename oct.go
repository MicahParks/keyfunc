package keyfunc

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

const (

	// ktyOct is the key type (kty) in the JWT header for oct.
	ktyOct = "oct"
)

// Oct parses a jsonWebKey and turns it into a raw byte slice (octet). This includes HMAC keys.
func (j *jsonWebKey) Oct() (publicKey ed25519.PublicKey, err error) {

	// Confirm everything needed is present.
	if j.K == "" {
		return nil, fmt.Errorf("%w: %s", ErrMissingAssets, ktyOct)
	}

	// Decode the octet key from Base64.
	var publicBytes []byte
	if publicBytes, err = base64.RawURLEncoding.DecodeString(j.K); err != nil {
		return nil, err
	}

	return publicBytes, nil
}
