package main

import (
	"log"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"

	"github.com/MicahParks/keyfunc"
)

func main() {

	// Get the JWKS URL.
	//
	// This is a sample JWKS service. Visit https://jwks-service.appspot.com/ and grab a token to test this example.
	// Example curl request:
	// curl -i  http://0.0.0.0:3001 -H "Authorization: Bearer eyJraWQiOiJmNTVkOWE0ZSIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJLZXNoYSIsImF1ZCI6IlRhc2h1YW4iLCJpc3MiOiJqd2tzLXNlcnZpY2UuYXBwc3BvdC5jb20iLCJleHAiOjE2MTkwMjUyMTEsImlhdCI6MTYxOTAyNTE3NywianRpIjoiMWY3MTgwNzAtZTBiOC00OGNmLTlmMDItMGE1M2ZiZWNhYWQwIn0.vetsI8W0c4Z-bs2YCVcPb9HsBm1BrMhxTBSQto1koG_lV-2nHwksz8vMuk7J7Q1sMa7WUkXxgthqu9RGVgtGO2xor6Ub0WBhZfIlFeaRGd6ZZKiapb-ASNK7EyRIeX20htRf9MzFGwpWjtrS5NIGvn1a7_x9WcXU9hlnkXaAWBTUJ2H73UbjDdVtlKFZGWM5VGANY4VG7gSMaJqCIKMxRPn2jnYbvPIYz81sjjbd-sc2-ePRjso7Rk6s382YdOm-lDUDl2APE-gqkLWdOJcj68fc6EBIociradX_ADytj-JYEI6v0-zI-8jSckYIGTUF5wjamcDfF5qyKpjsmdrZJA"
	jwksURL := "https://jwks-service.appspot.com/.well-known/jwks.json"

	// Create the keyfunc options. Use an error handler that logs.
	options := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.KeyFunc\nError: %s", err.Error())
		},
	}

	// Create the JWKS from the resource at the given URL.
	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		log.Fatalf("Failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
	}

	// Create the middleware provider.
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{

		// Use the correct version of the KeyFunc method.
		ValidationKeyGetter: jwks.KeyFuncF3T,

		// Always ensure that you set your signing method to avoid tokens choosing the "none" method.
		//
		// This shouldn't matter for this keyfunc package, as the JWKS should be trusted and determines the key type,
		// but it's good practice.
		// https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
		SigningMethod: jwt.SigningMethodRS256,
	})

	// Create an HTTP handler.
	var myHandler = http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {

		// Get the JWT from the request context.
		user := req.Context().Value("user")

		// Print the JWT claims.
		log.Println("JWT Claims:")
		for claim, value := range user.(*jwt.Token).Claims.(jwt.MapClaims) {
			log.Printf("  %s :%#v\n", claim, value)
		}

		// Write a 200 response.
		writer.WriteHeader(200)
	})

	// Wrap the handler with authentication.
	app := jwtMiddleware.Handler(myHandler)

	// Listen and serve forever.
	if err = http.ListenAndServe("0.0.0.0:3000", app); err != nil {
		panic(err.Error())
	}
}
