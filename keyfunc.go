package keyfunc

import (
	"context"
	"errors"
	"fmt"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrKeyfunc is returned when a keyfunc error occurs.
	ErrKeyfunc = errors.New("failed keyfunc")
)

// Keyfunc is meant to be used as the jwt.Keyfunc function for github.com/golang-jwt/jwt/v5. It uses
// github.com/MicahParks/jwkset as a JWK Set storage.
type Keyfunc interface {
	Keyfunc(token *jwt.Token) (any, error)
	Storage() jwkset.Storage
}

// Options are used to create a new Keyfunc.
type Options struct {
	Ctx          context.Context
	Storage      jwkset.Storage
	UseWhitelist []jwkset.USE
}

type keyfunc struct {
	ctx          context.Context
	storage      jwkset.Storage
	useWhitelist []jwkset.USE
}

// New creates a new Keyfunc.
func New(options Options) (Keyfunc, error) {
	ctx := options.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if options.Storage == nil {
		return nil, fmt.Errorf("%w: no JWK Set storage given in options", ErrKeyfunc)
	}
	k := keyfunc{
		storage:      options.Storage,
		ctx:          ctx,
		useWhitelist: options.UseWhitelist,
	}
	return k, nil
}

// NewDefault creates a new Keyfunc with a default JWK Set storage and options.
//
// This will launch "refresh goroutines" to refresh the remote HTTP resources.
func NewDefault(urls []string) (Keyfunc, error) {
	client, err := jwkset.NewDefaultClient(urls)
	if err != nil {
		return nil, err
	}
	options := Options{
		Storage: client,
	}
	return New(options)
}

func (k keyfunc) Keyfunc(token *jwt.Token) (any, error) {
	kidInter, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("%w: could not find kid in JWT header", ErrKeyfunc)
	}
	kid, ok := kidInter.(string)
	if !ok {
		return nil, fmt.Errorf("%w: could not convert kid in JWT header to string", ErrKeyfunc)
	}
	alg, ok := token.Header["alg"].(string)
	if !ok {
		// For test coverage purposes, this should be impossible to reach because the JWT package rejects a token
		// without an alg parameter in the header before calling jwt.Keyfunc.
		return nil, fmt.Errorf(`%w: the JWT header did not contain the "alg" parameter, which is required by RFC 7515 section 4.1.1`, ErrKeyfunc)
	}

	jwk, err := k.storage.KeyRead(k.ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("%w: could not read JWK from storage", errors.Join(err, ErrKeyfunc))
	}

	if a := jwk.Marshal().ALG.String(); a != "" && a != alg {
		return nil, fmt.Errorf(`%w: JWK "alg" parameter value %q does not match token "alg" parameter value %q`, ErrKeyfunc, a, alg)
	}
	if len(k.useWhitelist) > 0 {
		found := false
		for _, u := range k.useWhitelist {
			if jwk.Marshal().USE == u {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf(`%w: JWK "use" parameter value %q is not in whitelist %q`, ErrKeyfunc, jwk.Marshal().USE, k.useWhitelist)
		}
	}

	return jwk.Key(), nil
}
func (k keyfunc) Storage() jwkset.Storage {
	return k.storage
}
