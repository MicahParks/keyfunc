package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"

	"github.com/MicahParks/keyfunc/v3"
)

const (
	givenKeyID  = "my-key-id"
	remoteJWKS1 = `{"keys":[{"e":"AQAB","kid":"d2eb60d9-55e4-481c-8399-ccd3b638514b","kty":"RSA","n":"uxPctbWcIAMGKTBahOBymFYRFic1MtV-O3SYaUwLs8SJIQ8oMx3aSCRoZhqtJKtPyE5sT3K-zBW4cy5kC9AOMR6rKEnlI8MhUOEwOO9XXMqaohfexrbNIQRA6iJrfwICq2_90rU7sxVZUDO_2ZjMwgUwl8vxjINHj8WPd_t0gOPCJD-YUGpC1672WopiUoBSIb2rFXsJbe5qC3pSlPiGOpZ4vXjKdaptztrfBLlDxN14Lh0qsMqLBM0-p9pdpdd38fWN5Suv5CPvpK9SR1VdB5K7H5d6Srg3_AZdU4xTMym9MhSLccGDy6fWdBjChDNW-mkNDV3UhVGw_bgPzX2CAQ"}]}`
	remoteJWKS2 = `{"keys":[{"e":"AQAB","kid":"1ef9609e-859d-452e-964a-d0d4700169d6","kty":"RSA","n":"zP5x11PIMiYBUfnWZ7kxcrJVhYmm6sIMy6Q-uiCuCusvPGcmkCOIqqQYmZQxAYbfR8CrVVVF8fWPKfuyrOxCXzl4SmSZ9_WQkjNy4BntVJP1ulykp6suZDaeLufXm_tmE7_LJZvUY3q2aA0StUNJJVAdOAlrZgooLrgSPW3N9hqGHhiYcwX_4aBWPZ_vvrjARte5iUriF-64y0_M7n95jumcEiLOrskxO9_PjiObPAs9IxSfzoYcgezKw9Mhb1wZuDIf-6DFPcxGm3NGtzY6bjOghpG6lfZ8eG7S08InlskmKk-KqBEGieWqrNr0QKMI1Qv2iEtVuwN5jfXHLKCu-w"}]}`
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Emulate remote servers.
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(remoteJWKS1))
		if err != nil {
			log.Fatalf("Failed to write the JWK Set to the response.\nError: %s", err)
		}
	}))
	defer s1.Close()
	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(remoteJWKS2))
		if err != nil {
			log.Fatalf("Failed to write the JWK Set to the response.\nError: %s", err)
		}
	}))
	defer s2.Close()

	// Create the given keys.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate given key.\nError: %s", err)
	}
	metadata := jwkset.JWKMetadataOptions{
		ALG: jwkset.AlgEdDSA,
		KID: givenKeyID,
		USE: jwkset.UseSig,
	}
	options := jwkset.JWKOptions{
		Metadata: metadata,
	}
	jwk, err := jwkset.NewJWKFromKey(pub, options)
	if err != nil {
		log.Fatalf("Failed to create a JWK from the given HMAC secret.\nError: %s", err)
	}
	given := jwkset.NewMemoryStorage()
	err = given.KeyWrite(ctx, jwk)
	if err != nil {
		log.Fatalf("Failed to write the given JWK to the store.\nError: %s", err)
	}

	// Create the JWK Set HTTP clients.
	remoteJWKSets := make(map[string]jwkset.Storage)
	for _, u := range []string{s1.URL, s2.URL} {
		ur, err := url.ParseRequestURI(u)
		if err != nil {
			log.Fatalf("Failed to parse given URL %q: %s", u, err)
		}
		jwksetHTTPStorageOptions := jwkset.HTTPClientStorageOptions{
			Client:                    http.DefaultClient, // Could be replaced with a custom client.
			Ctx:                       ctx,                // Used to end background refresh goroutine.
			HTTPExpectedStatus:        http.StatusOK,
			HTTPMethod:                http.MethodGet,
			HTTPTimeout:               10 * time.Second,
			NoErrorReturnFirstHTTPReq: true, // Create storage regardless if the first HTTP request fails.
			RefreshErrorHandler: func(ctx context.Context, err error) {
				slog.Default().ErrorContext(ctx, "Failed to refresh HTTP JWK Set from remote HTTP resource.",
					"error", err,
					"url", ur.String(),
				)
			},
			RefreshInterval: time.Hour,
			Storage:         nil,
		}
		store, err := jwkset.NewStorageFromHTTP(ur, jwksetHTTPStorageOptions)
		if err != nil {
			log.Fatalf("Failed to create HTTP client storage for %q: %s", u, err)
		}
		remoteJWKSets[ur.String()] = store
	}

	// Create the JWK Set containing HTTP clients and given keys.
	jwksetHTTPClientOptions := jwkset.HTTPClientOptions{
		Given:             given,
		HTTPURLs:          remoteJWKSets,
		PrioritizeHTTP:    false,
		RefreshUnknownKID: rate.NewLimiter(rate.Every(5*time.Minute), 1),
	}
	combined, err := jwkset.NewHTTPClient(jwksetHTTPClientOptions)
	if err != nil {
		log.Fatalf("Failed to create HTTP client storage: %s", err)
	}

	// Create the keyfunc.Keyfunc.
	keyfuncOptions := keyfunc.Options{
		Ctx:          ctx,
		Storage:      combined,
		UseWhitelist: []jwkset.USE{jwkset.UseSig},
	}
	jwks, err := keyfunc.New(keyfuncOptions)
	if err != nil {
		log.Fatalf("Failed to create keyfunc.\nError: %s", err)
	}

	// Get a signed JWT.
	token := jwt.New(jwt.SigningMethodEdDSA)
	token.Header[jwkset.HeaderKID] = givenKeyID
	signed, err := token.SignedString(priv)
	if err != nil {
		log.Fatalf("Failed to sign a JWT.\nError: %s", err)
	}

	// Parse and validate the JWT.
	token, err = jwt.Parse(signed, jwks.Keyfunc)
	if err != nil {
		log.Fatalf("Failed to parse the JWT.\nError: %s", err)
	}
	if !token.Valid {
		log.Fatalf("The token is not valid.")
	}
	log.Println("The token is valid.")
}
