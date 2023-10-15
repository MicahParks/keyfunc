package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/MicahParks/keyfunc/v2"
)

const (
	givenKeyID  = "my-key-id"
	remoteJWKS1 = `{"keys":[{"e":"AQAB","kid":"d2eb60d9-55e4-481c-8399-ccd3b638514b","kty":"RSA","n":"uxPctbWcIAMGKTBahOBymFYRFic1MtV-O3SYaUwLs8SJIQ8oMx3aSCRoZhqtJKtPyE5sT3K-zBW4cy5kC9AOMR6rKEnlI8MhUOEwOO9XXMqaohfexrbNIQRA6iJrfwICq2_90rU7sxVZUDO_2ZjMwgUwl8vxjINHj8WPd_t0gOPCJD-YUGpC1672WopiUoBSIb2rFXsJbe5qC3pSlPiGOpZ4vXjKdaptztrfBLlDxN14Lh0qsMqLBM0-p9pdpdd38fWN5Suv5CPvpK9SR1VdB5K7H5d6Srg3_AZdU4xTMym9MhSLccGDy6fWdBjChDNW-mkNDV3UhVGw_bgPzX2CAQ"}]}`
	remoteJWKS2 = `{"keys":[{"e":"AQAB","kid":"1ef9609e-859d-452e-964a-d0d4700169d6","kty":"RSA","n":"zP5x11PIMiYBUfnWZ7kxcrJVhYmm6sIMy6Q-uiCuCusvPGcmkCOIqqQYmZQxAYbfR8CrVVVF8fWPKfuyrOxCXzl4SmSZ9_WQkjNy4BntVJP1ulykp6suZDaeLufXm_tmE7_LJZvUY3q2aA0StUNJJVAdOAlrZgooLrgSPW3N9hqGHhiYcwX_4aBWPZ_vvrjARte5iUriF-64y0_M7n95jumcEiLOrskxO9_PjiObPAs9IxSfzoYcgezKw9Mhb1wZuDIf-6DFPcxGm3NGtzY6bjOghpG6lfZ8eG7S08InlskmKk-KqBEGieWqrNr0QKMI1Qv2iEtVuwN5jfXHLKCu-w"}]}`
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(remoteJWKS1))
		if err != nil {
			log.Fatalf("Failed to write the JWKS to the response.\nError: %s", err.Error())
		}
	}))
	defer s1.Close()

	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(remoteJWKS2))
		if err != nil {
			log.Fatalf("Failed to write the JWKS to the response.\nError: %s", err.Error())
		}
	}))
	defer s2.Close()

	recommendedOpts := keyfunc.Options{
		Ctx: ctx,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	// Create the given keys.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate given key.\nError: %s", err.Error())
	}
	eddsaGiven := keyfunc.NewGivenEdDSA(pub, keyfunc.GivenKeyOptions{
		Algorithm: "EdDSA",
	})

	// Attach the given keys to a copy of one of the options.
	optsWithGiven := recommendedOpts
	optsWithGiven.GivenKeys = make(map[string]keyfunc.GivenKey)
	optsWithGiven.GivenKeys[givenKeyID] = eddsaGiven

	multiple := map[string]keyfunc.Options{
		s1.URL: optsWithGiven, // Only one of the options needs the given keys.
		s2.URL: recommendedOpts,
	}

	opts := keyfunc.MultipleOptions{
		KeySelector: keyfunc.KeySelectorFirst,
	}
	multi, err := keyfunc.GetMultiple(multiple, opts)
	if err != nil {
		log.Fatalf("Failed to create multiple JWKS.\nError: %s", err.Error())
	}

	token := jwt.New(jwt.SigningMethodEdDSA)
	token.Header["kid"] = givenKeyID
	signed, err := token.SignedString(priv)
	if err != nil {
		log.Fatalf("Failed to sign a JWT.\nError: %s", err.Error())
	}

	token, err = jwt.Parse(signed, multi.Keyfunc)
	if err != nil {
		log.Fatalf("Failed to parse the JWT.\nError: %s", err.Error())
	}

	if !token.Valid {
		log.Fatalf("The token is not valid.")
	}
	log.Println("The token is valid.")
}
