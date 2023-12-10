package main

import (
	"context"
	"log"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"

	"github.com/MicahParks/keyfunc/v3"
)

func main() {
	// Create a context that, when cancelled, ends the JWKS background refresh goroutine.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create the given keys.
	hmacSecret := []byte("example secret")
	const givenKID = "givenKID"

	// Turn the given HMAC key into a jwkset.JWK.
	marshalOptions := jwkset.JWKMarshalOptions{
		Private: true,
	}
	metadata := jwkset.JWKMetadataOptions{
		ALG: jwkset.AlgHS256,
		KID: givenKID, // Required for keyfunc.
		USE: jwkset.UseSig,
	}
	jwkOptions := jwkset.JWKOptions{
		Marshal:  marshalOptions,
		Metadata: metadata,
	}
	jwk, err := jwkset.NewJWKFromKey(hmacSecret, jwkOptions)
	if err != nil {
		log.Fatalf("Failed to create a JWK from the given HMAC secret.\nError: %s.", err)
	}

	// Create JWK Set storage. This implements the jwkset.Storage interface.
	store := jwkset.NewMemoryStorage()
	err = store.KeyWrite(ctx, jwk)
	if err != nil {
		log.Fatalf("Failed to write the given JWK to the store.\nError: %s.", err)
	}

	// Create the keyfunc.Keyfunc.
	options := keyfunc.Options{
		Storage: store,
		Ctx:     ctx,
	}
	jwks, err := keyfunc.New(options)
	if err != nil {
		log.Fatalf("Failed to create JWKS from resource at the given URL.\nError: %s", err)
	}

	// Create a JWT signed by the give HMAC key.
	token := jwt.New(jwt.SigningMethodHS256)
	token.Header["kid"] = givenKID
	jwtB64, err := token.SignedString(hmacSecret)
	if err != nil {
		log.Fatalf("Failed to sign a JWT with the HMAC secret.\nError: %s.", err)
	}

	// Parse and validate a JWT. This one is signed by the given HMAC key.
	token, err = jwt.Parse(jwtB64, jwks.Keyfunc)
	if err != nil {
		log.Fatalf("Failed to parse the JWT signed by the given HMAC key.\nError: %s.", err)
	}
	if !token.Valid {
		log.Fatalf("The token signed by the given HMAC key is not valid.")
	}
	log.Println("The token signed by the given HMAC key is valid.")

	// Parse and validate a JWT. This one is signed by a non-given key and is expired.
	jwtB64 = "eyJraWQiOiJlZThkNjI2ZCIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJXZWlkb25nIiwiYXVkIjoiVGFzaHVhbiIsImlzcyI6Imp3a3Mtc2VydmljZS5hcHBzcG90LmNvbSIsImlhdCI6MTYzMTM2OTk1NSwianRpIjoiNDY2M2E5MTAtZWU2MC00NzcwLTgxNjktY2I3NDdiMDljZjU0In0.LwD65d5h6U_2Xco81EClMa_1WIW4xXZl8o4b7WzY_7OgPD2tNlByxvGDzP7bKYA9Gj--1mi4Q4li4CAnKJkaHRYB17baC0H5P9lKMPuA6AnChTzLafY6yf-YadA7DmakCtIl7FNcFQQL2DXmh6gS9J6TluFoCIXj83MqETbDWpL28o3XAD_05UP8VLQzH2XzyqWKi97mOuvz-GsDp9mhBYQUgN3csNXt2v2l-bUPWe19SftNej0cxddyGu06tXUtaS6K0oe0TTbaqc3hmfEiu5G0J8U6ztTUMwXkBvaknE640NPgMQJqBaey0E4u0txYgyvMvvxfwtcOrDRYqYPBnA"
	token, err = jwt.Parse(jwtB64, jwks.Keyfunc)
	if err != nil {
		log.Fatalf("Failed to parse the JWT signed by a non-given key in the remote JWKS.\nError: %s.", err)
	}
	if !token.Valid {
		log.Fatalf("The token signed by a non-given key in the remote JWKS is not valid.")
	}
	log.Println("The token signed by a non-given key in the remote JWKS is valid.")
}
