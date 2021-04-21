[![Go Report Card](https://goreportcard.com/badge/github.com/MicahParks/keyfunc)](https://goreportcard.com/report/github.com/MicahParks/keyfunc) [![Go Reference](https://pkg.go.dev/badge/github.com/MicahParks/keyfunc.svg)](https://pkg.go.dev/github.com/MicahParks/keyfunc)

# keyfunc

Purpose of this package is to provide a
[`jwt.KeyFunc`](https://pkg.go.dev/github.com/dgrijalva/jwt-go@v3.2.0+incompatible#Keyfunc) for the
[github.com/dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go)
and [github.com/auth0/go-jwt-middleware](https://github.com/auth0/go-jwt-middleware) packages using a JSON Web Key Set
(JWKS) for parsing JSON Web Tokens (JWTs).

It's common for an identity provider, such as [Keycloak](https://www.keycloak.org/) to expose a JWKS via an HTTPS
endpoint. This package has the ability to consume that JWKS and produce a
[`jwt.KeyFunc`](https://pkg.go.dev/github.com/dgrijalva/jwt-go@v3.2.0+incompatible#Keyfunc). It is important that a JWKS
endpoint is using HTTPS to ensure the keys are from the correct trusted source.

There are no dependencies other than [github.com/dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go)
and [github.com/form3tech-oss/jwt-go](https://github.com/form3tech-oss/jwt-go) for this repository.

## Supported Algorithms

It is recommended to only use this package for asymmetric signing keys. If you are using HMAC signing keys, this Go
package may be unnecessary as the algorithm is symmetric, meaning the key is pre-shared. In this case a JWKS is likely
not be the best solution.

Currently, this package supports JWTs signed with an `alg` that matches one of the following:

* `ES256`
* `ES384`
* `ES512`
* `PS256`
* `PS384`
* `PS512`
* `RS256`
* `RS384`
* `RS512`

Additionally, the supported elliptical curve types are below:

* `P-256`
* `P-384`
* `P-521`

If there are cryptographic algorithms, curve types, or something else already standardized that you'd like supported in
this Go package, please open an issue or pull request.

## Basic usage

Please also see the `examples` directory.

```go
import "github.com/MicahParks/keyfunc"
```

### Step 1: Acquire the JWKS URL (optional)

A JWKS URL is not required, one can be created directly from JSON with the
[`keyfunc.New`](https://pkg.go.dev/github.com/MicahParks/keyfunc#New) function.

```go
// Get the JWKS URL from an environment variable.
jwksURL := os.Getenv("JWKS_URL")

// Confirm the environment variable is not empty.
if jwksURL == "" {
	log.Fatalln("JWKS_URL environment variable must be populated.")
}
```

### Step 2: Get the JWKS via HTTP

```go
// Create the JWKS from the resource at the given URL.
jwks, err := keyfunc.Get(jwksURL)
if err != nil {
	log.Fatalf("Failed to get the JWKS from the given URL.\nError: %s", err.Error())
}
```

Additional options can be passed to the [`keyfunc.Get`](https://pkg.go.dev/github.com/MicahParks/keyfunc#Get) function
via variadic arguments. See [`keyfunc.Options`](https://pkg.go.dev/github.com/MicahParks/keyfunc#Options).

### Step 3: Use the [`keyfunc.JWKS`](https://pkg.go.dev/github.com/MicahParks/keyfunc#JWKS) 's [`JWKS.KeyFunc`](https://pkg.go.dev/github.com/MicahParks/keyfunc#JWKS.KeyFunc) method as the [`jwt.KeyFunc`](https://pkg.go.dev/github.com/dgrijalva/jwt-go@v3.2.0+incompatible#Keyfunc) when parsing tokens

```go
// Parse the JWT.
token, err := jwt.Parse(jwtB64, jwks.KeyFunc)
if err != nil {
	return nil, fmt.Errorf("failed to parse token: %w", err)
}
```

The [`JWKS.KeyFunc`](https://pkg.go.dev/github.com/MicahParks/keyfunc#JWKS.KeyFunc) method will automatically select the
key with the matching `kid` (if present) and return its public key as the correct Go type to its caller.

## Support for [`github.com/auth0/go-jwt-middleware`](https://github.com/auth0/go-jwt-middleware)

Auth0 provides a useful middleware exposing a HTTP Handler that can be used to wrap other handlers with OIDC authentication checks. This lib can provide the `ValidationKeyGetter` used in the [`jwtmiddleware.Options`](https://pkg.go.dev/github.com/auth0/go-jwt-middleware#Options) struct to allow the handler to use a JWKS URL as a source for keys.

### Step 1: Acquire the JWKS URL (optional)
A JWKS URL is not required, one can be created directly from JSON with the
[`keyfunc.New`](https://pkg.go.dev/github.com/MicahParks/keyfunc#New) function.

```go
// Get the JWKS URL from an environment variable.
jwksURL := os.Getenv("JWKS_URL")

// Confirm the environment variable is not empty.
if jwksURL == "" {
	log.Fatalln("JWKS_URL environment variable must be populated.")
}
```

### Step 2: Get the JWKS via HTTP

```go
// Create the JWKS from the resource at the given URL.
jwks, err := keyfunc.Get(jwksURL)
if err != nil {
	log.Fatalf("Failed to get the JWKS from the given URL.\nError: %s", err.Error())
}
```

Additional options can be passed to the [`keyfunc.Get`](https://pkg.go.dev/github.com/MicahParks/keyfunc#Get) function
via variadic arguments. See [`keyfunc.Options`](https://pkg.go.dev/github.com/MicahParks/keyfunc#Options).


### Step 3: Initialize the Middleware with the JWKS Keyfunc

Note the usage of [`JWKS.KeyFuncF3T`](https://pkg.go.dev/github.com/MicahParks/keyfunc#JWKS.KeyFuncF3T). The [github.com/auth0/go-jwt-middleware](https://github.com/auth0/go-jwt-middleware) module uses a fork of the original [github.com/dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go) called [github.com/form3tech-oss/jwt-go](https://github.com/form3tech-oss/jwt-go) and thus requires a token from a different package.

```go
// Create the middleware provider
jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
  // Use the correct version of the KeyFunc here to support the forked lib used in jwtmiddleware
  ValidationKeyGetter: jwks.KeyFuncF3T,
  // Always ensure that you set your signing method to avoid tokens choosing the "none" method
  SigningMethod: jwt.SigningMethodRS256,
})

app := jwtMiddleware.Handler(myHandler)
http.ListenAndServe("0.0.0.0:3000", app)
```

See [auth0/go-jwt-middleware](https://github.com/auth0/go-jwt-middleware) for more details on the middleware itself.

## Test coverage

Test coverage is currently at `83.1%`.

This is with current and expired JWTs, but the hard coded ones are now expired. Using non-expired JWTs would require
signing JWTs during testing and would allow for additional error checking. But a bit overkill since I've already done
that error checking when the JWTs were valid with no changes. A PR for this that does not introduce any dependencies is
welcome though.

## Additional features

* A background refresh of the JWKS keys can be performed. This is possible by passing
  [`keyfunc.Options`](https://pkg.go.dev/github.com/MicahParks/keyfunc#Options) via a variadic argument to the
  [`keyfunc.Get`](https://pkg.go.dev/github.com/MicahParks/keyfunc#Get) function.
	* A custom background refresh interval can be specified.
	* A custom background refresh request context timeout can be specified. Defaults to one minute.
	* A custom background refresh error handling function can be specified. If none is specified, errors go unhandled
	  silently.
* JWTs with a previously unseen `kid` can prompt an automatic refresh of the remote JWKS resource.
* A custom HTTP client can be used. This is possible by passing
  [`keyfunc.Options`](https://pkg.go.dev/github.com/MicahParks/keyfunc#Options) via a variadic argument to the
  [`keyfunc.Get`](https://pkg.go.dev/github.com/MicahParks/keyfunc#Get) function.

## TODO

- [ ] Add HMAC support?
