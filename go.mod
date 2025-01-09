module github.com/MicahParks/keyfunc/v3

go 1.21

require (
	github.com/MicahParks/jwkset v0.6.0
	github.com/golang-jwt/jwt/v5 v5.2.1
	golang.org/x/time v0.9.0
)

retract (
	v3.3.0 // Incorrect return type in keyfunc.Keyfunc interface
	[v3.0.0, v3.3.5] // HTTP client only overwrites and appends JWK to local cache during refresh: https://github.com/MicahParks/jwkset/issues/40
)
