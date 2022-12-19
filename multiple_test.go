package keyfunc_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v4"

	"github.com/MicahParks/keyfunc"
)

const (
	jwks1 = `{"keys":[{"alg":"EdDSA","crv":"Ed25519","kid":"uniqueKID","kty":"OKP","x":"1IlXuWBIkjYbAXm5Hk5mvsbPq0skO3-G_hX1Cw7CY-8"},{"alg":"EdDSA","crv":"Ed25519","kid":"collisionKID","kty":"OKP","x":"IbQyt_GPqUJImuAgStdixWdadZGvzTPS_mKlOjmuOYU"}]}`
	jwks2 = `{"keys":[{"alg":"EdDSA","crv":"Ed25519","kid":"collisionKID","kty":"OKP","x":"IbQyt_GPqUJImuAgStdixWdadZGvzTPS_mKlOjmuOYU"}]}`
)

func TestMultipleJWKS(t *testing.T) {
	server1 := createTestServer([]byte(jwks1))
	defer server1.Close()

	server2 := createTestServer([]byte(jwks2))
	defer server2.Close()

	const (
		collisionJWT = "eyJhbGciOiJFZERTQSIsImtpZCI6ImNvbGxpc2lvbktJRCIsInR5cCI6IkpXVCJ9.e30.WXKmhyHjHQFXZ8dXfj07RvwKAgHB3EdGU1jeKUEY-wajgsRsHuhnotX1WqDSlngwGerEitnIcdMGViW_HNUCAA"
		uniqueJWT    = "eyJhbGciOiJFZERTQSIsImtpZCI6InVuaXF1ZUtJRCIsInR5cCI6IkpXVCJ9.e30.egdT5_vXYKIM7UfsyewYaR63tS9T9JvKwUJs7Srj6wG9JHXMvN9Ftq0rJGem07ESVtN5OtlcJOaMgSbtxnc6Bg"
	)

	m := map[string]keyfunc.Options{
		server1.URL: {},
		server2.URL: {},
	}

	multiJWKS, err := keyfunc.GetMultiple(m, keyfunc.MultipleOptions{})
	if err != nil {
		t.Fatalf("failed to get multiple JWKS: %v", err)
	}

	token, err := jwt.Parse(collisionJWT, multiJWKS.Keyfunc)
	if err != nil {
		t.Fatalf("failed to parse collision JWT: %v", err)
	}
	if !token.Valid {
		t.Fatalf("collision JWT is invalid")
	}

	token, err = jwt.Parse(uniqueJWT, multiJWKS.Keyfunc)
	if err != nil {
		t.Fatalf("failed to parse unique JWT: %v", err)
	}
	if !token.Valid {
		t.Fatalf("unique JWT is invalid")
	}

	sets := multiJWKS.JWKSets()
	if len(sets) != 2 {
		t.Fatalf("expected 2 JWKS, got %d", len(sets))
	}
}

func createTestServer(body []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}
