package main

import (
	"log"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"github.com/MicahParks/keyfunc"
)

func main() {

	// Get the JWKs URL.
	//
	// This is a sample JWKs service. Visit https://jwks-service.appspot.com/ and grab a token to test this example.
	jwksURL := "https://jwks-service.appspot.com/.well-known/jwks.json"

	// Create the keyfunc options. Use an error handler that logs. Timeout the initial JWKs refresh request after 10
	// seconds. This timeout is also used to create the initial context.Context for keyfunc.Get.
	refreshTimeout := time.Second * 10
	options := keyfunc.Options{
		RefreshTimeout: &refreshTimeout,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
	}

	// Create the JWKs from the resource at the given URL.
	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		log.Fatalf("Failed to create JWKs from resource at the given URL.\nError: %s", err.Error())
	}

	// Get a JWT to parse.
	jwtB64 := "eyJraWQiOiJmNTVkOWE0ZSIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJLZXNoYSIsImF1ZCI6IlRhc2h1YW4iLCJpc3MiOiJqd2tzLXNlcnZpY2UuYXBwc3BvdC5jb20iLCJleHAiOjE2MTkwMjUyMTEsImlhdCI6MTYxOTAyNTE3NywianRpIjoiMWY3MTgwNzAtZTBiOC00OGNmLTlmMDItMGE1M2ZiZWNhYWQwIn0.vetsI8W0c4Z-bs2YCVcPb9HsBm1BrMhxTBSQto1koG_lV-2nHwksz8vMuk7J7Q1sMa7WUkXxgthqu9RGVgtGO2xor6Ub0WBhZfIlFeaRGd6ZZKiapb-ASNK7EyRIeX20htRf9MzFGwpWjtrS5NIGvn1a7_x9WcXU9hlnkXaAWBTUJ2H73UbjDdVtlKFZGWM5VGANY4VG7gSMaJqCIKMxRPn2jnYbvPIYz81sjjbd-sc2-ePRjso7Rk6s382YdOm-lDUDl2APE-gqkLWdOJcj68fc6EBIociradX_ADytj-JYEI6v0-zI-8jSckYIGTUF5wjamcDfF5qyKpjsmdrZJA"

	// Parse the JWT.
	var token *jwt.Token
	if token, err = jwt.Parse(jwtB64, jwks.Keyfunc); err != nil {
		log.Fatalf("Failed to parse the JWT.\nError: %s", err.Error())
	}

	// Check if the token is valid.
	if !token.Valid {
		log.Fatalf("The token is not valid.")
	}
	log.Println("The token is valid.")
}
