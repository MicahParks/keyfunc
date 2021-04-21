package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	"github.com/MicahParks/keyfunc"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  user := r.Context().Value("user")
  fmt.Fprintf(w, "This is an authenticated request")
  fmt.Fprintf(w, "Claim content:\n")
  for k, v := range user.(*jwt.Token).Claims.(jwt.MapClaims) {
    fmt.Fprintf(w, "%s :\t%#v\n", k, v)
  }
})

func main() {
	// Get the JWKS URL.
	//
	// This is a sample JWKS service. Visit https://jwks-service.appspot.com/ and grab a token to test this example code.
	jwksURL := "https://jwks-service.appspot.com/.well-known/jwks.json"

	// Create the keyfunc options. Refresh the JWKS every hour and log errors.
	refreshInterval := time.Hour
	options := keyfunc.Options{
		RefreshInterval: &refreshInterval,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.KeyFunc\nError: %s", err.Error())
		},
	}

	// Create the JWKS from the resource at the given URL.
	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		log.Fatalf("Failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
	}

	// Create the middleware provider
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		// Use the correct version of the KeyFunc here to support the forked lib used in jwtmiddleware
		ValidationKeyGetter: jwks.KeyFuncF3T,
		// Always ensure that you set your signing method to avoid tokens choosing the "none" method
		SigningMethod: jwt.SigningMethodRS256,
	})

	// Wrap the handler with authentication
	app := jwtMiddleware.Handler(myHandler)
	http.ListenAndServe("0.0.0.0:3000", app)
}
