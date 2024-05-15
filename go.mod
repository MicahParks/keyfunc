module github.com/MicahParks/keyfunc/v3

go 1.21

require (
	github.com/MicahParks/jwkset v0.5.18
	github.com/golang-jwt/jwt/v5 v5.2.0
	golang.org/x/time v0.5.0
)

retract v3.3.0 // Incorrect return type in keyfunc.Keyfunc interface
