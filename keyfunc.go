package keyfunc

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

var (

	// ErrKID indicates that the JWT had an invalid kid.
	ErrKID = errors.New("the JWT has an invalid kid")
)

// Keyfunc is a compatibility function that matches the signature of github.com/golang-jwt/jwt/v4's jwt.Keyfunc
// function.
func (j *JWKS) Keyfunc(token *jwt.Token) (interface{}, error) {
	kidInter, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("%w: could not find kid in JWT header", ErrKID)
	}
	kid, ok := kidInter.(string)
	if !ok {
		return nil, fmt.Errorf("%w: could not convert kid in JWT header to string", ErrKID)
	}

	return j.getKey(kid)
}
