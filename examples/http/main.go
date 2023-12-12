package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"

	"github.com/MicahParks/keyfunc/v3"
)

const (
	keyID = "my-key-id"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a cryptographic key.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate given key.\nError: %s", err)
	}

	// Turn the key into a JWK.
	marshalOptions := jwkset.JWKMarshalOptions{
		Private: true,
	}
	metadata := jwkset.JWKMetadataOptions{
		KID: keyID,
	}
	options := jwkset.JWKOptions{
		Marshal:  marshalOptions,
		Metadata: metadata,
	}
	jwk, err := jwkset.NewJWKFromKey(pub, options)
	if err != nil {
		log.Fatalf("Failed to create a JWK from the given key.\nError: %s", err)
	}

	// Write the JWK to the server's storage.
	serverStore := jwkset.NewMemoryStorage()
	err = serverStore.KeyWrite(ctx, jwk)
	if err != nil {
		log.Fatalf("Failed to write the JWK to the server's storage.\nError: %s", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawJWKS, err := serverStore.JSONPublic(ctx)
		if err != nil {
			log.Fatalf("Failed to get the server's JWKS.\nError: %s", err)
		}
		_, _ = w.Write(rawJWKS)
	}))

	// Sign a JWT with this key.
	token := jwt.New(jwt.SigningMethodEdDSA)
	token.Header[jwkset.HeaderKID] = keyID
	signed, err := token.SignedString(priv)
	if err != nil {
		log.Fatalf("Failed to sign a JWT.\nError: %s", err)
	}

	// Create the keyfunc.Keyfunc.
	k, err := keyfunc.NewDefault([]string{server.URL})
	if err != nil {
		log.Fatalf("Failed to create a keyfunc.Keyfunc from the server's URL.\nError: %s", err)
	}

	// Parse the JWT.
	parsed, err := jwt.Parse(signed, k.Keyfunc)
	if err != nil {
		log.Fatalf("Failed to parse the JWT.\nError: %s", err)
	}

	// Validate the JWT.
	if !parsed.Valid {
		log.Fatalf("The JWT is not valid.")
	}
	log.Println("The JWT is valid.")
}
