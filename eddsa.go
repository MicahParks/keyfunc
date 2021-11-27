package keyfunc

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

const (

	// ktyEC is the key type (kty) in the JWT header for EdDSA.
	ktyOKP = "OKP"
)

// EdDSA parses a jsonWebKey and turns it into a EdDSA public key.
func (j *jsonWebKey) EdDSA() (publicKey ed25519.PublicKey, err error) {

	// Confirm everything needed is present.
	if j.X == "" {
		return nil, fmt.Errorf("%w: %s", ErrMissingAssets, ktyOKP)
	}

	// Decode the public key from Base64.
	//
	// According to RFC 8037, this is from Base64 URL bytes.
	// https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.2
	var publicBytes []byte
	if publicBytes, err = base64.RawURLEncoding.DecodeString(j.X); err != nil {
		return nil, err
	}

	return publicBytes, nil
}
