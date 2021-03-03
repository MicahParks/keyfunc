package jwks

import (
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

var (

	// ErrUnsupportedKeyType indicates the JWT key type is an unsupported type.
	ErrUnsupportedKeyType = errors.New("the JWT key type is unsupported")
)

// KeyFunc is a compatibility function that matches the signature of github.com/dgrijalva/jwt-go's KeyFunc function.
func (k Keystore) KeyFunc() (keyFunc jwt.Keyfunc) {
	return func(token *jwt.Token) (interface{}, error) {

		// Determine the key type and return the appropriate key type.
		switch keyAlg := token.Header["alg"]; keyAlg {
		case RS256:
			return k.RSA(token.Header["kid"].(string))
		default:
			return nil, fmt.Errorf("%w: %s: feel free to add a feature request or contribute to https://github.com/MicahParks/jwks", ErrUnsupportedKeyType, keyAlg)
		}
	}
}
