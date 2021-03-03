[![Go Report Card](https://goreportcard.com/badge/github.com/MicahParks/jwks)](https://goreportcard.com/report/github.com/MicahParks/jwks) [![Go Reference](https://pkg.go.dev/badge/github.com/MicahParks/jwks.svg)](https://pkg.go.dev/github.com/MicahParks/jwks)

# jwks

Don't get too excited. This repository is meant to be just enough to grab some RSA public keys from Keycloak's JWKS for
verifying JWTs. RSA keys only.

## TODO

- [ ] Once a key has been decoded, keep a reference and return that instead, so it's not decoded on every call.
