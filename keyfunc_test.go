package keyfunc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
)

const (
	keyID = "my-key-id"
)

func TestNew(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair. Error: %s", err)
	}
	jwk, err := jwkset.NewJWKFromKey(priv, jwkset.JWKOptions{})
	if err != nil {
		t.Fatalf("Failed to create JWK from ED25519 private key. Error: %s", err)
	}

	serverStore := jwkset.NewMemoryStorage()
	err = serverStore.KeyWrite(ctx, jwk)
	if err != nil {
		t.Fatalf("Failed to write ED25519 public key to server store. Error: %s", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawJWKS, err := serverStore.JSONPrivate(ctx)
		if err != nil {
			t.Fatalf("Failed to get JWK Set JSON from server store. Error: %s", err)
		}
		_, _ = w.Write(rawJWKS)
	}))

	token := jwt.New(jwt.SigningMethodEdDSA)
	token.Header[jwkset.HeaderKID] = keyID
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("Failed to sign JWT. Error: %s", err)
	}

	clientStore, err := jwkset.NewDefaultHTTPClient([]string{server.URL})
	if err != nil {
		t.Fatalf("Failed to create client store. Error: %s", err)
	}
	options := Options{
		Ctx:          ctx,
		Storage:      clientStore,
		UseWhitelist: []jwkset.USE{jwkset.UseSig},
	}
	k, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create Keyfunc. Error: %s", err)
	}

	_, err = jwt.Parse(signed, k.Keyfunc)
	if !errors.Is(err, ErrKeyfunc) {
		t.Fatalf("Expected ErrKeyfunc for missing Key ID in header, but got %s.", err)
	}

	metadata := jwkset.JWKMetadataOptions{
		KID: keyID,
		USE: jwkset.UseSig,
	}
	jwkOptions := jwkset.JWKOptions{
		Metadata: metadata,
	}
	jwk, err = jwkset.NewJWKFromKey(priv, jwkOptions)
	if err != nil {
		t.Fatalf("Failed to create JWK from ED25519 private key. Error: %s", err)
	}
	err = serverStore.KeyWrite(ctx, jwk)
	if err != nil {
		t.Fatalf("Failed to write ED25519 public key to server store. Error: %s", err)
	}

	clientStore, err = jwkset.NewDefaultHTTPClient([]string{server.URL})
	if err != nil {
		t.Fatalf("Failed to create client store. Error: %s", err)
	}
	options.Storage = clientStore
	k, err = New(options)
	if err != nil {
		t.Fatalf("Failed to create Keyfunc. Error: %s", err)
	}

	_, err = jwt.Parse(signed, k.Keyfunc)
	if err != nil {
		t.Fatalf("Failed to parse JWT. Error: %s", err)
	}

	if !reflect.DeepEqual(k.Storage(), clientStore) {
		t.Fatalf("Expected client store, but got something else.")
	}

	_, err = NewDefault([]string{server.URL})
	if err != nil {
		t.Fatalf("Failed to create Keyfunc. Error: %s", err)
	}
}

func TestNewErr(t *testing.T) {
	_, err := New(Options{})
	if !errors.Is(err, ErrKeyfunc) {
		t.Error("Expected ErrKeyfunc, but got nil.")
	}
}
