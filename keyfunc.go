package keyfunc

import (
	"errors"
	"fmt"

	legacy "github.com/dgrijalva/jwt-go"
	f3t "github.com/form3tech-oss/jwt-go"
	"github.com/golang-jwt/jwt"
)

var (

	// ErrKID indicates that the JWT had an invalid kid.
	ErrKID = errors.New("the JWT has an invalid kid")

	// ErrUnsupportedKeyType indicates the JWT key type is an unsupported type.
	ErrUnsupportedKeyType = errors.New("the JWT key type is unsupported")
)

// KeyFunc is a compatibility function that matches the signature of github.com/dgrijalva/jwt-go's KeyFunc function.
func (j *JWKs) KeyFunc(token *jwt.Token) (interface{}, error) {

	// Get the kid from the token header.
	kidInter, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("%w: could not find kid in JWT header", ErrKID)
	}
	kid, ok := kidInter.(string)
	if !ok {
		return nil, fmt.Errorf("%w: could not convert kid in JWT header to string", ErrKID)
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

// KeyFuncF3T is a compatibility function that matches the signature of github.com/form3tech-oss/jwt-go's KeyFunc
// function.
func (j *JWKs) KeyFuncF3T(f3tToken *f3t.Token) (interface{}, error) {
	token := &jwt.Token{
		Raw:       f3tToken.Raw,
		Method:    f3tToken.Method,
		Header:    f3tToken.Header,
		Claims:    f3tToken.Claims,
		Signature: f3tToken.Signature,
		Valid:     f3tToken.Valid,
	}
	return j.KeyFunc(token)
}

// KeyFuncLegacy is a compatibility function that matches the signature of the legacy github.com/dgrijalva/jwt-go's
// KeyFunc function.
func (j *JWKs) KeyFuncLegacy(legacyToken *legacy.Token) (interface{}, error) {
	token := &jwt.Token{
		Raw:       legacyToken.Raw,
		Method:    legacyToken.Method,
		Header:    legacyToken.Header,
		Claims:    legacyToken.Claims,
		Signature: legacyToken.Signature,
		Valid:     legacyToken.Valid,
	}
	return j.KeyFunc(token)
}
