package keyfunc

import (
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

var (

	// ErrKID indicates that the JWT had an invalid kid.
	ErrKID = errors.New("the JWT has an invalid kid")

	// ErrUnsupportedKeyType indicates the JWT key type is an unsupported type.
	ErrUnsupportedKeyType = errors.New("the JWT key type is unsupported")
)

// KeyFunc is a compatibility function that matches the signature of github.com/dgrijalva/jwt-go's KeyFunc function.
func (j *JWKS) KeyFunc(token *jwt.Token) (interface{}, error) {

	// Get the kid from the token header.
	kidInter, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("%w: could not find kid in JWT header", ErrKID)
	}
	kid, ok := kidInter.(string)
	if !ok {
		return nil, fmt.Errorf("%w: could not convert KID in JWT header to string", ErrKID)
	}

	// Get the JSONKey.
	jsonKey, err := j.getKey(kid)
	if err != nil {
		return nil, err
	}

	// Determine the key's algorithm and return the appropriate public key.
	switch keyAlg := token.Header["alg"]; keyAlg {
	case es256, es384, es512:
		return jsonKey.ECDSA()
	case ps256, ps384, ps512, rs256, rs384, rs512:
		return jsonKey.RSA()
	default:
		return nil, fmt.Errorf("%w: %s: feel free to add a feature request or contribute to https://github.com/MicahParks/keyfunc", ErrUnsupportedKeyType, keyAlg)
	}
}
