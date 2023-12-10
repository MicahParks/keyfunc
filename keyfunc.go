package keyfunc

import (
	"context"
	"fmt"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
)

// Keyfunc is meant to be used as the jwt.Keyfunc function for github.com/golang-jwt/jwt/v5. It uses
// github.com/MicahParks/jwkset as a JWK Set client.
type Keyfunc interface {
	Client() jwkset.Client
	Keyfunc(token *jwt.Token) (any, error)
}

// Options are used to create a new Keyfunc.
type Options struct {
	Client       jwkset.Client
	Ctx          context.Context
	UseWhitelist []jwkset.USE
}

type keyfunc struct {
	client       jwkset.Client
	ctx          context.Context
	useWhitelist []jwkset.USE
}

// New creates a new Keyfunc.
func New(options Options) (Keyfunc, error) {
	ctx := options.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if options.Client == nil {
		return nil, fmt.Errorf("%w: no JWK Set client given in options", ErrOptions)
	}
	k := keyfunc{
		client:       options.Client,
		ctx:          ctx,
		useWhitelist: options.UseWhitelist,
	}
	return k, nil
}

// NewDefault creates a new Keyfunc with a default JWK Set client and options.
//
// This will launch "refresh goroutines" to refresh the remote HTTP resources.
func NewDefault(urls []string) (Keyfunc, error) {
	client, err := jwkset.NewDefaultClient(urls)
	if err != nil {
		return nil, err
	}
	options := Options{
		Client: client,
	}
	return New(options)
}

func (k keyfunc) Client() jwkset.Client {
	return k.client
}
func (k keyfunc) Keyfunc(token *jwt.Token) (any, error) {
	kidInter, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("%w: could not find kid in JWT header", ErrKID)
	}
	kid, ok := kidInter.(string)
	if !ok {
		return nil, fmt.Errorf("%w: could not convert kid in JWT header to string", ErrKID)
	}
	alg, ok := token.Header["alg"].(string)
	if !ok {
		// For test coverage purposes, this should be impossible to reach because the JWT package rejects a token
		// without an alg parameter in the header before calling jwt.Keyfunc.
		return nil, fmt.Errorf(`%w: the JWT header did not contain the "alg" parameter, which is required by RFC 7515 section 4.1.1`, ErrJWKAlgMismatch)
	}

	jwk, err := k.client.ReadKey(k.ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("%w: could not read JWK from storage", err)
	}

	if a := jwk.Marshal().ALG.String(); a != "" && a != alg {
		return nil, fmt.Errorf(`%w: JWK "alg" parameter value %q does not match token "alg" parameter value %q`, ErrJWKAlgMismatch, a, alg)
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
			return nil, fmt.Errorf(`%w: JWK "use" parameter value %q is not in whitelist %q`, ErrJWKUseMismatch, jwk.Marshal().USE, k.useWhitelist)
		}
	}

	return jwk.Key(), nil
}
