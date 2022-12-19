package keyfunc_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MicahParks/keyfunc"
)

const (
	jwks1 = `{"keys":[{"alg":"EdDSA","crv":"Ed25519","kid":"keyCollision","kty":"OKP","x":"w_a0ZgEjNuD_YrNtexSfVcZkJKzzRmf4Jv7gDmRkTj0"}]}`
	jwks2 = `{"keys":[{"alg":"EdDSA","crv":"Ed25519","kid":"keyCollision","kty":"OKP","x":"hDLmETJ2XnYMhVCrXjr0yv76ytPWZN3QiwSvStOYhj0"},{"alg":"EdDSA","crv":"Ed25519","kid":"uniqueKey","kty":"OKP","x":"hDLmETJ2XnYMhVCrXjr0yv76ytPWZN3QiwSvStOYhj0"}]}`
)

func TestMultipleJWKS(t *testing.T) {
	server1 := createTestServer([]byte(jwks1))
	defer server1.Close()

	server2 := createTestServer([]byte(jwks2))
	defer server2.Close()

	m := map[string]keyfunc.Options{
		server1.URL: {},
		server2.URL: {},
	}

	multiJWKS, err := keyfunc.GetMultiple(m, keyfunc.MultipleOptions{})
	if err != nil {
		t.Fatalf("failed to get multiple JWKS: %v", err)
	}

}

func createTestServer(body []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}
