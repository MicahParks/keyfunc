package keyfunc

import (
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

func TestBadCurve(t *testing.T) {
	const (
		badJWKS = `{"keys":[{"kty":"EC","crv":"BAD","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"1"}]}`
		someJWT = `eyJhbGciOiJFUzI1NiIsImtpZCI6IjEiLCJ0eXAiOiJKV1QifQ.e30.Q1EeyWUv6XEA0gMLwTFoNhx7Hq1MbVwjI2k9FZPSa-myKW1wYn1X6rHtRyuV-2MEzvimCskFD-afL7UzvdWBQg`
	)

	jwks, err := NewJSON(json.RawMessage(badJWKS))
	if err != nil {
		t.Fatalf("Failed to create JWKS from JSON: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic")
		}
	}()

	if _, err = jwt.Parse(someJWT, jwks.Keyfunc); err == nil {
		t.Fatal("No error for bad curve")
	}
}
