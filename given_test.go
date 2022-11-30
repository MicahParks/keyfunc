package keyfunc_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v4"

	"github.com/MicahParks/keyfunc"
	"github.com/MicahParks/keyfunc/examples/custom/method"
)

const (
	// algAttribute is the JSON attribute for the JWT encryption algorithm.
	algAttribute = "alg"

	// kidAttribute is the JSON attribute for the Key ID.
	kidAttribute = "kid"

	// testKID is the testing KID.
	testKID = "testkid"
)

// TestNewGivenCustom tests that a custom jwt.SigningMethod can be used to create a JWKS and a proper jwt.Keyfunc.
func TestNewGivenCustom(t *testing.T) {
	jwt.RegisterSigningMethod(method.CustomAlgHeader, func() jwt.SigningMethod {
		return method.EmptyCustom{}
	})

	givenKeys := make(map[string]keyfunc.GivenKey)
	key := addCustom(givenKeys, testKID)

	jwks := keyfunc.NewGiven(givenKeys)

	token := jwt.New(method.EmptyCustom{})
	token.Header[algAttribute] = method.CustomAlgHeader
	token.Header[kidAttribute] = testKID

	signParseValidate(t, token, key, jwks)
}

// TestNewGivenCustomAlg tests that a custom jwt.SigningMethod can be used to create a JWKS and a proper jwt.Keyfunc.
func TestNewGivenCustomAlg(t *testing.T) {
	jwt.RegisterSigningMethod(method.CustomAlgHeader, func() jwt.SigningMethod {
		return method.EmptyCustom{}
	})

	const key = "test-key"
	givenKeys := make(map[string]keyfunc.GivenKey)
	givenKeys[testKID] = keyfunc.NewGivenCustomWithOptions(key, keyfunc.GivenKeyOptions{
		Algorithm: method.CustomAlgHeader,
	})

	jwks := keyfunc.NewGiven(givenKeys)

	token := jwt.New(method.EmptyCustom{})
	token.Header[algAttribute] = method.CustomAlgHeader
	token.Header[kidAttribute] = testKID

	signParseValidate(t, token, key, jwks)
}

// TestNewGivenCustomAlg_NegativeCase tests that a custom jwt.SigningMethod can be used to create
// a JWKS and a proper jwt.Keyfunc and that a token with a non-matching algorithm will be rejected.
func TestNewGivenCustomAlg_NegativeCase(t *testing.T) {
	jwt.RegisterSigningMethod(method.CustomAlgHeader, func() jwt.SigningMethod {
		return method.EmptyCustom{}
	})

	const key = jwt.UnsafeAllowNoneSignatureType // Allow the "none" JWT "alg" header value for golang-jwt.
	givenKeys := make(map[string]keyfunc.GivenKey)
	givenKeys[testKID] = keyfunc.NewGivenCustomWithOptions(key, keyfunc.GivenKeyOptions{
		Algorithm: method.CustomAlgHeader,
	})

	jwks := keyfunc.NewGiven(givenKeys)

	token := jwt.New(method.EmptyCustom{})
	token.Header[algAttribute] = jwt.SigningMethodNone.Alg()
	token.Header[kidAttribute] = testKID

	jwtB64, err := token.SignedString(key)
	if err != nil {
		t.Fatalf(logFmt, "Failed to sign the JWT.", err)
	}

	parsed, err := jwt.NewParser().Parse(jwtB64, jwks.Keyfunc)
	if !errors.Is(err, keyfunc.ErrJWKAlgMismatch) {
		t.Fatalf("Failed to return ErrJWKAlgMismatch: %v.", err)
	}

	if parsed.Valid {
		t.Fatalf("The JWT was valid.")
	}
}

// TestNewGivenKeyECDSA tests that a generated ECDSA key can be added to the JWKS and create a proper jwt.Keyfunc.
func TestNewGivenKeyECDSA(t *testing.T) {
	givenKeys := make(map[string]keyfunc.GivenKey)
	key, err := addECDSA(givenKeys, testKID)
	if err != nil {
		t.Fatalf(err.Error())
	}

	jwks := keyfunc.NewGiven(givenKeys)

	token := jwt.New(jwt.SigningMethodES256)
	token.Header[kidAttribute] = testKID

	signParseValidate(t, token, key, jwks)
}

// TestNewGivenKeyEdDSA tests that a generated EdDSA key can be added to the JWKS and create a proper jwt.Keyfunc.
func TestNewGivenKeyEdDSA(t *testing.T) {
	givenKeys := make(map[string]keyfunc.GivenKey)
	key, err := addEdDSA(givenKeys, testKID)
	if err != nil {
		t.Fatalf(err.Error())
	}

	jwks := keyfunc.NewGiven(givenKeys)

	token := jwt.New(jwt.SigningMethodEdDSA)
	token.Header[kidAttribute] = testKID

	signParseValidate(t, token, key, jwks)
}

// TestNewGivenKeyHMAC tests that a generated HMAC key can be added to a JWKS and create a proper jwt.Keyfunc.
func TestNewGivenKeyHMAC(t *testing.T) {
	givenKeys := make(map[string]keyfunc.GivenKey)
	key, err := addHMAC(givenKeys, testKID)
	if err != nil {
		t.Fatalf(err.Error())
	}

	jwks := keyfunc.NewGiven(givenKeys)

	token := jwt.New(jwt.SigningMethodHS256)
	token.Header[kidAttribute] = testKID

	signParseValidate(t, token, key, jwks)
}

// TestNewGivenKeyRSA tests that a generated RSA key can be added to the JWKS and create a proper jwt.Keyfunc.
func TestNewGivenKeyRSA(t *testing.T) {
	givenKeys := make(map[string]keyfunc.GivenKey)
	key, err := addRSA(givenKeys, testKID)
	if err != nil {
		t.Fatalf(err.Error())
	}

	jwks := keyfunc.NewGiven(givenKeys)

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header[kidAttribute] = testKID

	signParseValidate(t, token, key, jwks)
}

// TestNewGivenKeysFromJSON tests that parsing GivenKeys from JSON can be used to create a JWKS and a proper jwt.Keyfunc.
func TestNewGivenKeysFromJSON(t *testing.T) {
	// Construct a JWKS JSON containing a JWK for which we know the private key and thus can sign a token.
	key := []byte("test-hmac-secret")
	const testJSON = `{
		"keys": [
			{
				"kid": "testkid",
				"kty": "oct",
				"alg": "HS256",
				"use": "sig",
				"k": "dGVzdC1obWFjLXNlY3JldA"
			}
		]
	}`

	givenKeys, err := keyfunc.NewGivenKeysFromJSON([]byte(testJSON))
	if err != nil {
		t.Fatalf(logFmt, "Failed to parse given keys from JSON.", err)
	}

	jwks := keyfunc.NewGiven(givenKeys)

	token := jwt.New(jwt.SigningMethodHS256)
	token.Header[kidAttribute] = testKID

	signParseValidate(t, token, key, jwks)
}

// TestNewGivenKeysFromJSON_BadParse makes sure bad JSON returns an error.
func TestNewGivenKeysFromJSON_BadParse(t *testing.T) {
	const testJSON = "{not the best syntax"
	_, err := keyfunc.NewGivenKeysFromJSON([]byte(testJSON))
	if err == nil {
		t.Fatalf("Expected a JSON parse error")
	}
}

// addCustom adds a new key wto the given keys map. The new key is using a test jwt.SigningMethod.
func addCustom(givenKeys map[string]keyfunc.GivenKey, kid string) (key string) {
	key = ""
	givenKeys[kid] = keyfunc.NewGivenCustomWithOptions(key, keyfunc.GivenKeyOptions{
		Algorithm: method.CustomAlgHeader,
	})
	return key
}

// addECDSA adds a new ECDSA key to the given keys map.
func addECDSA(givenKeys map[string]keyfunc.GivenKey, kid string) (key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDSA key: %w", err)
	}

	givenKeys[kid] = keyfunc.NewGivenECDSACustomWithOptions(&key.PublicKey, keyfunc.GivenKeyOptions{
		Algorithm: jwt.SigningMethodES256.Alg(),
	})

	return key, nil
}

// addEdDSA adds a new EdDSA key to the given keys map.
func addEdDSA(givenKeys map[string]keyfunc.GivenKey, kid string) (key ed25519.PrivateKey, err error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDSA key: %w", err)
	}

	givenKeys[kid] = keyfunc.NewGivenEdDSACustomWithOptions(pub, keyfunc.GivenKeyOptions{
		Algorithm: jwt.SigningMethodEdDSA.Alg(),
	})

	return key, nil
}

// addHMAC creates a new HMAC secret stuff.
func addHMAC(givenKeys map[string]keyfunc.GivenKey, kid string) (secret []byte, err error) {
	secret = make([]byte, sha256.BlockSize)
	_, err = rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create HMAC secret: %w", err)
	}

	givenKeys[kid] = keyfunc.NewGivenHMACCustomWithOptions(secret, keyfunc.GivenKeyOptions{
		Algorithm: jwt.SigningMethodHS256.Alg(),
	})

	return secret, nil
}

// addRSA adds a new RSA key to the given keys map.
func addRSA(givenKeys map[string]keyfunc.GivenKey, kid string) (key *rsa.PrivateKey, err error) {
	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to create RSA key: %w", err)
	}

	givenKeys[kid] = keyfunc.NewGivenRSACustomWithOptions(&key.PublicKey, keyfunc.GivenKeyOptions{
		Algorithm: jwt.SigningMethodRS256.Alg(),
	})

	return key, nil
}

// signParseValidate signs the JWT, parses it using the given JWKS, then validates it.
func signParseValidate(t *testing.T, token *jwt.Token, key interface{}, jwks *keyfunc.JWKS) {
	jwtB64, err := token.SignedString(key)
	if err != nil {
		t.Fatalf(logFmt, "Failed to sign the JWT.", err)
	}

	parsed, err := jwt.Parse(jwtB64, jwks.Keyfunc)
	if err != nil {
		t.Fatalf(logFmt, "Failed to parse the JWT.", err)
	}

	if !parsed.Valid {
		t.Fatalf("The JWT was not valid.")
	}
}
