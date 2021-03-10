[![Go Report Card](https://goreportcard.com/badge/github.com/MicahParks/jwks)](https://goreportcard.com/report/github.com/MicahParks/jwks) [![Go Reference](https://pkg.go.dev/badge/github.com/MicahParks/jwks.svg)](https://pkg.go.dev/github.com/MicahParks/jwks)

# keyfunc

The sole purpose of this package is to provide a
[`jwt.KeyFunc`](https://pkg.go.dev/github.com/dgrijalva/jwt-go@v3.2.0+incompatible#Keyfunc) for the
[github.com/dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go) package using a JSON Web Key Set (JWKS) for parsing
JSON Web Tokens (JWTs).

It's common for an identity provider, such as [Keycloak](https://www.keycloak.org/) to expose a JWKS via an HTTPS
endpoint. This package has the ability to consume that JWKS and produce a
[`jwt.KeyFunc`](https://pkg.go.dev/github.com/dgrijalva/jwt-go@v3.2.0+incompatible#Keyfunc). It is important that a JWKS
endpoint is using HTTPS to ensure the keys are from the correct trusted source.

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

### Step 1: Acquire the JWKS URL

```go
// Get the JWKS URL from an environment variable.
jwksURL := os.Getenv("JWKS_URL")

// Confirm the environment variable is not empty.
if jwksURL == "" {
	log.Fatalln("JWKS_URL environment variable must be populated.")
}
```

#### Step 2: Get the JWKS via HTTP

```go
// Create the JWKS from the resource at the given URL.
jwks, err := keyfunc.Get(jwksURL)
if err != nil {
	log.Fatalf("Failed to get the JWKS from the given URL.\nError: %s", err.Error())
}
```

The `keyfunc.JWKS` can also be created manually from JSON by the `keyfunc.New()` function.

#### Step 3: Use the `keyfunc.JWKS`'s `KeyFunc()` method as the `jwt.KeyFunc` when parsing tokens

```go
// Parse the JWT.
token, err := jwt.Parse(jwtB64, jwks.KeyFunc())
if err != nil {
	return nil, fmt.Errorf("failed to parse token: %w", err)
}
```

The `KeyFunc()` method will automatically select the key with the matching `kid` (if present) and return its public key
as the correct Go type to its caller.

## Test coverage
TODO

## Additional features

* A background refresh of the JWKS keys can be performed. This is possible by passing `keyfunc.Options` via a variadic
  argument to the `keyfunc.Get()` function.
    * A custom background refresh interval can be specified.
    * A custom background refresh request context timeout can be specified. Defaults to one minute.
    * A custom background refresh error handling function can be specified. If none is specified, errors go unhandled
      silently.
* A custom HTTP client can be used. This is possible by passing `keyfunc.Options` via a variadic argument to the
  `keyfunc.Get()` function.

## TODO

- [ ] Add HMAC support?
