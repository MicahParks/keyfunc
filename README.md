[![Go Report Card](https://goreportcard.com/badge/github.com/MicahParks/keyfunc)](https://goreportcard.com/report/github.com/MicahParks/keyfunc) [![Go Reference](https://pkg.go.dev/badge/github.com/MicahParks/keyfunc.svg)](https://pkg.go.dev/github.com/MicahParks/keyfunc)

# keyfunc

The sole purpose of this package is to provide a
[`jwt.KeyFunc`](https://pkg.go.dev/github.com/dgrijalva/jwt-go@v3.2.0+incompatible#Keyfunc) for the
[github.com/dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go) package using a JSON Web Key Set (JWKS) for parsing
JSON Web Tokens (JWTs).

It's common for an identity provider, such as [Keycloak](https://www.keycloak.org/) to expose a JWKS via an HTTPS
endpoint. This package has the ability to consume that JWKS and produce a
[`jwt.KeyFunc`](https://pkg.go.dev/github.com/dgrijalva/jwt-go@v3.2.0+incompatible#Keyfunc). It is important that a JWKS
endpoint is using HTTPS to ensure the keys are from the correct trusted source.

There are no dependencies other than [github.com/dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go) for this
repository.

## Supported Algorithms

It is recommended to only use this package for asymmetric signing keys, If you are using HMAC signing keys, this Go
package is largely unnecessary as the algorithm is symmetric, meaning the key is pre-shared. In this case a JWKS is
likely not be the best solution.

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
[`keyfunc.New()`](https://pkg.go.dev/github.com/MicahParks/keyfunc#New) function.

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

Addition options can be passed to the [`keyfunc.Get()`](https://pkg.go.dev/github.com/MicahParks/keyfunc#Get) function
via variadic arguments. See [`keyfunc.Options`](https://pkg.go.dev/github.com/MicahParks/keyfunc#Options).

### Step 3: Use the [`keyfunc.JWKS`](https://pkg.go.dev/github.com/MicahParks/keyfunc#JWKS) 's [`JWKS.KeyFunc()`](https://pkg.go.dev/github.com/MicahParks/keyfunc#JWKS.KeyFunc) method as the `jwt.KeyFunc` when parsing tokens

```go
// Parse the JWT.
token, err := jwt.Parse(jwtB64, jwks.KeyFunc)
if err != nil {
	return nil, fmt.Errorf("failed to parse token: %w", err)
}
```

The [`JWKS.KeyFunc()`](https://pkg.go.dev/github.com/MicahParks/keyfunc#JWKS.KeyFunc) method will automatically select
the key with the matching `kid` (if present) and return its public key as the correct Go type to its caller.

## Test coverage

Test coverage is currently at `81.6%`.

This is with current and expired JWTs, but the hard coded ones are now expired.
Using non-expired JWTs would require signing JWTs during testing and would allow for additional error checking. But a
bit overkill since I've already done that error checking when the JWTs were valid with no changes. A PR for this that
does not introduce any dependencies is welcome though.

## Additional features

* A background refresh of the JWKS keys can be performed. This is possible by passing
  [`keyfunc.Options`](https://pkg.go.dev/github.com/MicahParks/keyfunc#Options) via a variadic argument to the
  [`keyfunc.Get()`](https://pkg.go.dev/github.com/MicahParks/keyfunc#Get) function.
    * A custom background refresh interval can be specified.
    * A custom background refresh request context timeout can be specified. Defaults to one minute.
    * A custom background refresh error handling function can be specified. If none is specified, errors go unhandled
      silently.
* A custom HTTP client can be used. This is possible by passing
  [`keyfunc.Options`](https://pkg.go.dev/github.com/MicahParks/keyfunc#Options) via a variadic argument to the
  [`keyfunc.Get()`](https://pkg.go.dev/github.com/MicahParks/keyfunc#Get) function.

## TODO

- [ ] Add HMAC support?
