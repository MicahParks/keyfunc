package main

import (
	"log"

	"github.com/golang-jwt/jwt/v5"

	"github.com/MicahParks/keyfunc/v3"
)

func main() {
	// Get the JWK Set URL.
	//
	// This is a local Keycloak JWK Set endpoint for the master realm.
	jwksURL := "http://localhost:8080/auth/realms/master/protocol/openid-connect/certs"

	// Create the keyfunc.Keyfunc.
	jwks, err := keyfunc.NewDefault([]string{jwksURL})
	if err != nil {
		log.Fatalf("Failed to create JWK Set from resource at the given URL.\nError: %s", err)
	}

	// Get a JWT to parse.
	jwtB64 := "eyJhbGciOiJQUzM4NCIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJMeDFGbWF5UDJZQnR4YXFTMVNLSlJKR2lYUktudzJvdjVXbVlJTUctQkxFIn0.eyJleHAiOjE2MTU0MDY5ODIsImlhdCI6MTYxNTQwNjkyMiwianRpIjoiMGY2NGJjYTktYjU4OC00MWFhLWFkNDEtMmFmZDM2OGRmNTFkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.Rxrq41AxbWKIQHWv-Tkb7rqwel3sKT_R_AGvn9mPIHqhw1m7nsQWcL9t2a_8MI2hCwgWtYdgTF1xxBNmb2IW3CZkML5nGfcRrFvNaBHd3UQEqbFKZgnIX29h5VoxekyiwFaGD-0RXL83jF7k39hytEzTatwoVjZ-frga0KFl-nLce3OwncRXVCGmxoFzUsyu9TQFS2Mm_p0AMX1y1MAX1JmLC3WFhH3BohhRqpzBtjSfs_f46nE1-HKjqZ1ERrAc2fmiVJjmG7sT702JRuuzrgUpHlMy2juBG4DkVcMlj4neJUmCD1vZyZBRggfaIxNkwUhHtmS2Cp9tOcwNu47tSg"

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
