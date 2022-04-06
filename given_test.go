package keyfunc_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	jwt.RegisterSigningMethod(method.CustomAlg, func() jwt.SigningMethod {
		return method.EmptyCustom{}
	})

	givenKeys := make(map[string]keyfunc.GivenKey)
	key := addCustom(givenKeys, testKID)

	jwks := keyfunc.NewGiven(givenKeys)

	token := jwt.New(method.EmptyCustom{})
	token.Header[algAttribute] = method.CustomAlg
	token.Header[kidAttribute] = testKID

	signParseValidate(t, token, key, jwks)
}

// TestNewGivenKeyECDSA tests that a generated ECDSA key can be added to the JWKS and create a proper jwt.Keyfunc.
func TestNewGivenKeyECDSA(t *testing.T) {
	givenKeys := make(map[string]keyfunc.GivenKey)
	key, err := addECDSA(givenKeys, testKID)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
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
		t.Errorf(err.Error())
		t.FailNow()
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
		t.Errorf(err.Error())
		t.FailNow()
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
		t.Errorf(err.Error())
		t.FailNow()
	}

	jwks := keyfunc.NewGiven(givenKeys)

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header[kidAttribute] = testKID

	signParseValidate(t, token, key, jwks)
}

// addCustom adds a new key wto the given keys map. The new key is using a test jwt.SigningMethod.
func addCustom(givenKeys map[string]keyfunc.GivenKey, kid string) (key string) {
	key = ""
	givenKeys[kid] = keyfunc.NewGivenCustom(key)
	return key
}

// addECDSA adds a new ECDSA key to the given keys map.
func addECDSA(givenKeys map[string]keyfunc.GivenKey, kid string) (key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDSA key: %w", err)
	}

	givenKeys[kid] = keyfunc.NewGivenECDSA(&key.PublicKey)

	return key, nil
}

// addEdDSA adds a new EdDSA key to the given keys map.
func addEdDSA(givenKeys map[string]keyfunc.GivenKey, kid string) (key ed25519.PrivateKey, err error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDSA key: %w", err)
	}

	givenKeys[kid] = keyfunc.NewGivenEdDSA(pub)

	return key, nil
}

// addHMAC creates a new HMAC secret stuff.
func addHMAC(givenKeys map[string]keyfunc.GivenKey, kid string) (secret []byte, err error) {
	secret = make([]byte, sha256.BlockSize)
	_, err = rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create HMAC secret: %w", err)
	}

	givenKeys[kid] = keyfunc.NewGivenHMAC(secret)

	return secret, nil
}

// addRSA adds a new RSA key to the given keys map.
func addRSA(givenKeys map[string]keyfunc.GivenKey, kid string) (key *rsa.PrivateKey, err error) {
	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to create RSA key: %w", err)
	}

	givenKeys[kid] = keyfunc.NewGivenRSA(&key.PublicKey)

	return key, nil
}

// signParseValidate signs the JWT, parses it using the given JWKS, then validates it.
func signParseValidate(t *testing.T, token *jwt.Token, key interface{}, jwks *keyfunc.JWKS) {
	jwtB64, err := token.SignedString(key)
	if err != nil {
		t.Errorf("Failed to sign the JWT.\nError: %s", err.Error())
		t.FailNow()
	}

	parsed, err := jwt.Parse(jwtB64, jwks.Keyfunc)
	if err != nil {
		t.Errorf("Failed to parse the JWT.\nError: %s.", err.Error())
		t.FailNow()
	}

	if !parsed.Valid {
		t.Errorf("The JWT was not valid.")
		t.FailNow()
	}
}
