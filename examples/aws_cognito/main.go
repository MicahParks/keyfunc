package main

import (
	"fmt"
	"log"

	"github.com/golang-jwt/jwt/v5"

	"github.com/MicahParks/keyfunc/v3"
)

func main() {
	// Get the JWKS URL from your AWS region and userPoolId.
	//
	// See the AWS docs here:
	// https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
	regionID := ""   // TODO Get the region ID for your AWS Cognito instance.
	userPoolID := "" // TODO Get the user pool ID of your AWS Cognito instance.
	jwksURL := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", regionID, userPoolID)

	jwks, err := keyfunc.NewDefault([]string{jwksURL})
	if err != nil {
		log.Fatalf("Failed to create JWKS from resource at the given URL.\nError: %s", err)
	}

	// Get a JWT to parse.
	jwtB64 := "eyJraWQiOiJmNTVkOWE0ZSIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJLZXNoYSIsImF1ZCI6IlRhc2h1YW4iLCJpc3MiOiJqd2tzLXNlcnZpY2UuYXBwc3BvdC5jb20iLCJleHAiOjE2MTkwMjUyMTEsImlhdCI6MTYxOTAyNTE3NywianRpIjoiMWY3MTgwNzAtZTBiOC00OGNmLTlmMDItMGE1M2ZiZWNhYWQwIn0.vetsI8W0c4Z-bs2YCVcPb9HsBm1BrMhxTBSQto1koG_lV-2nHwksz8vMuk7J7Q1sMa7WUkXxgthqu9RGVgtGO2xor6Ub0WBhZfIlFeaRGd6ZZKiapb-ASNK7EyRIeX20htRf9MzFGwpWjtrS5NIGvn1a7_x9WcXU9hlnkXaAWBTUJ2H73UbjDdVtlKFZGWM5VGANY4VG7gSMaJqCIKMxRPn2jnYbvPIYz81sjjbd-sc2-ePRjso7Rk6s382YdOm-lDUDl2APE-gqkLWdOJcj68fc6EBIociradX_ADytj-JYEI6v0-zI-8jSckYIGTUF5wjamcDfF5qyKpjsmdrZJA"

	// Parse the JWT.
	token, err := jwt.Parse(jwtB64, jwks.Keyfunc)
	if err != nil {
		log.Fatalf("Failed to parse the JWT.\nError: %s", err)
	}

	// Check if the token is valid.
	if !token.Valid {
		log.Fatalf("The token is not valid.")
	}
	log.Println("The token is valid.")
}
