[![Go Report Card](https://goreportcard.com/badge/github.com/MicahParks/jwks)](https://goreportcard.com/report/github.com/MicahParks/jwks) [![Go Reference](https://pkg.go.dev/badge/github.com/MicahParks/jwks.svg)](https://pkg.go.dev/github.com/MicahParks/jwks)

# jwks

The scope of this package is to implement just enough of the JWKS specification to read a JWKS via HTTP and validate
JWTs via compatible functions. Validating is done through
[github.com/dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go). This package helps by exporting a
[`jwt.KeyFunc`](https://pkg.go.dev/github.com/dgrijalva/jwt-go@v3.2.0+incompatible#Keyfunc).

Currently, this package only supports JWTs signed with the `alg` of `RS256` (for Keycloak).

## Example

TODO

## TODO

- [ ] Make an example in the README.md.
