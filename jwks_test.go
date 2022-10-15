package keyfunc_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"github.com/MicahParks/keyfunc"
)

const (
	// emptyJWKSJSON is a hard-coded empty JWKS in JSON format.
	emptyJWKSJSON = `{"keys":[]}`

	// logFmt is an error log formatting string.
	logFmt = "%s\nError: %s"

	// jwksFilePath is the full path of th JWKS file on the test HTTP server.
	jwksFilePath = "/example_jwks.json"

	// tokenUseEnc is a token encrypted with a key whose "use" parameter is "enc".
	tokenUseEnc = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZFdpdGhCYWRVc2UiLCJ0eXAiOiJKV1QifQ.eyJmb28iOiJiYXIifQ.NKUjRgfqNZNCckL2yyiZc0ot_-BxtwYiknrILmsSnNapkOB32gMfRPTyc_j-UsIqw19FrDSBNk31blxSW40X3ubXp56hpwbcqE0nj9EvDyZoUWmtMl6pXIGPnTK5y-rNgS8i1IeeejNAQDYe8LOtCw_jE8CpOW5MBZzxdwjntPHGCWu4FCgrBu1ugth20B7WnuCHETa0xQ2NvXIX0W54JDbk_hdWTqjP4Bo7BvcGB6-5xZ1AaiiXjnOOuBrIMwTrZ-wtdTOjmSaWrcH94A8wDk263fSkhRLjM77d5IljIILT4a6nRHVSsgBfhblYevtX6NWBgllvQ_Hr_uuaT_b15A"
)

var (
	// jwksJSON is a embedded JWKS in JSON format.
	//go:embed example_jwks.json
	jwksJSON string
)

// TestInvalidServer performs initialization + refresh initialization with a server providing invalid data.
// The test ensures that background refresh goroutine does not cause any trouble in case of init failure.
func TestInvalidServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write(nil)
		if err != nil {
			t.Fatalf(logFmt, "Failed to write empty response.", err)
		}
	}))
	defer server.Close()

	testingRefreshErrorHandler := func(err error) {
		t.Fatalf(logFmt, "Unhandled JWKS error.", err)
	}

	refreshInterval := time.Second
	options := keyfunc.Options{
		RefreshInterval:     refreshInterval,
		RefreshErrorHandler: testingRefreshErrorHandler,
	}

	_, err := keyfunc.Get(server.URL, options)
	if err == nil {
		t.Fatalf("Creation of *keyfunc.JWKS with invalid server must fail.")
	}
}

// TestJWKS performs a table test on the JWKS code.
func TestJWKS(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "*")
	if err != nil {
		t.Fatalf(logFmt, "Failed to create a temporary directory.", err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Fatalf(logFmt, "Failed to remove temporary directory.", err)
		}
	}()

	jwksFile := filepath.Join(tempDir, jwksFilePath)

	err = os.WriteFile(jwksFile, []byte(jwksJSON), 0600)
	if err != nil {
		t.Fatalf(logFmt, "Failed to write JWKS file to temporary directory.", err)
	}

	server := httptest.NewServer(http.FileServer(http.Dir(tempDir)))
	defer server.Close()

	testingRefreshInterval := time.Second
	testingRateLimit := time.Millisecond * 500
	testingRefreshTimeout := time.Second
	testingRefreshErrorHandler := func(err error) {
		panic(fmt.Sprintf(logFmt, "Unhandled JWKS error.", err))
	}

	jwksURL := server.URL + jwksFilePath

	options := []keyfunc.Options{
		{}, // Default options.
		{
			Client: http.DefaultClient, // Should be ineffectual. Just for code coverage.
		},
		{
			Ctx: context.Background(), // Should be ineffectual. Just for code coverage.
		},
		{
			RefreshErrorHandler: testingRefreshErrorHandler,
		},
		{
			RefreshInterval: testingRefreshInterval,
		},
		{
			RefreshRateLimit: testingRateLimit,
		},
		{
			RefreshTimeout: testingRefreshTimeout,
		},
	}

	for _, opts := range options {
		jwks, err := keyfunc.Get(jwksURL, opts)
		if err != nil {
			t.Fatalf(logFmt, "Failed to get JWKS from testing URL.", err)
		}

		testCases := []struct {
			token string
		}{
			{""}, // Empty JWT.
			{"eyJhbGciOiJFUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJDR3QwWldTNExjNWZhaUtTZGkwdFUwZmpDQWR2R1JPUVJHVTlpUjd0VjBBIn0.eyJleHAiOjE2MTU0MDY4NjEsImlhdCI6MTYxNTQwNjgwMSwianRpIjoiYWVmOWQ5YjItN2EyYy00ZmQ4LTk4MzktODRiMzQ0Y2VmYzZhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.iQ77QGoPDNjR2oWLu3zT851mswP8J-h_nrGhs3fpa_tFB3FT1deKPGkjef9JOTYFI-CIVxdCFtW3KODOaw9Nrw"},                                                                                                                                                                                                                                                                 // Signing algorithm ES256.
			{"eyJhbGciOiJFUzM4NCIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUVkFBZXQ2M08zeHlfS0s2X2J4Vkl1N1JhM196MXdsQjU0M0Zid2k1VmFVIn0.eyJleHAiOjE2MTU0MDY4OTAsImlhdCI6MTYxNTQwNjgzMCwianRpIjoiYWNhNDU4NTItZTE0ZS00MjgxLTljZTQtN2ZiNzVkMTg1MWJmIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.oHFT-RvbNNT6p4_tIoZzr4IS88bZqy20cJhF6FZCIXALZ2dppoOjutanPVxzuLC5axG3P71noVghNUF8X44bTShP1boLrlde2QKmj5GxDR-oNEb9ES_zC10rZ5I76CwR"},                                                                                                                                                                                                                       // Signing algorithm ES384.
			{"eyJhbGciOiJFUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJlYkp4bm05QjNRREJsakI1WEpXRXU3MnF4NkJhd0RhTUFod3o0YUtQa1EwIn0.eyJleHAiOjE2MTU0MDY5MDksImlhdCI6MTYxNTQwNjg0OSwianRpIjoiMjBhMGI1MTMtN2E4My00OGQ2LThmNDgtZmQ3NDc1N2Y4OWRiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.AdR59BCvGlctL5BMgXlpJBBToKTPG4SVa-oJKBqE7qxvTSBwAQM5D3uUc2toM3NAUERSMKOLTJfzfxenNRixrDMnAcrdFHgEY10vsDp6uqA7NMUevHE5f7jiAVK1talXS9O41IEnR2DKbAG0GgjIA2WHLhUgftG2uNN8LMKI2QSbLCfM"},                                                                                                                                                                       // Signing algorithm ES512.
			{"eyJhbGciOiJFUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJlYkp4bm05QjNRREJsakI1WEpXRXU3MnF4NkJhd0RhTUFod3o0YUtQa1EwIn0.eyJleHAiOjE2MTU0MDY5MDksImlhdCI6MTYxNTQwNjg0OSwianRpIjoiMjBhMGI1MTMtN2E4My00OGQ2LThmNDgtZmQ3NDc1N2Y4OWRiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.AdR59BCvGlctL5BMgXlpJBBToKTPG4SVa-oJKBqE7qxvTSBwAQM5D3uUc2toM3NAUERSMKOLTJfzfxenNRixrDMnAcrdFHgEY10vsDp6uqA7NMUevHE5f7jiAVK1talXS9O41IEnR2DKbAG0GgjIA2WHLhUgftG2uNN8LMKI2QSbLCfM"},                                                                                                                                                                       // ECDSA inter.
			{"eyJhbGciOiJQUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ6WGV3MFVKMWg2UTRDQ2NkXzl3eE16dmNwNWNFQmlmSDBLV3JDejJLeXhjIn0.eyJleHAiOjE2MTU0MDY5NjIsImlhdCI6MTYxNTQwNjkwMiwianRpIjoiNWIyZGY5N2EtNDQyOS00ZTA0LWFkMzgtOWZmNjVlZDU2MTZjIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.tafkUwLXm3lyyqJHwAGwFPN3IO0rCrESJnVcIuI1KHPSKogn5DgWqR3B9QCvqIusqlxhGW7MvOhG-9dIy62ciKGQFDRFA9T46TMm9t8O80TnhYTB8ImX90xYuf6E74k1RiqRVcubFWKHWlhKjqXMM4dD2l8VwqL45E6kHpNDvzvILKAfrMgm0vHsfi6v5rf32HLp6Ox1PvpKrM1kDgsdXm6scgAGJCTbOQB2Pzc-i8cyFPeuckbeL4zbM3-Odqc-eI-3pXevMzUB608J3fRpQK1W053kU7iG9RFC-5nBwvrBlN4Lff_X1R3JBLkFcA0wJeFYtIFnMm6lVbA7nwa0Xg"}, // Signing algorithm PS256.
			{"eyJhbGciOiJQUzM4NCIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJMeDFGbWF5UDJZQnR4YXFTMVNLSlJKR2lYUktudzJvdjVXbVlJTUctQkxFIn0.eyJleHAiOjE2MTU0MDY5ODIsImlhdCI6MTYxNTQwNjkyMiwianRpIjoiMGY2NGJjYTktYjU4OC00MWFhLWFkNDEtMmFmZDM2OGRmNTFkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.Rxrq41AxbWKIQHWv-Tkb7rqwel3sKT_R_AGvn9mPIHqhw1m7nsQWcL9t2a_8MI2hCwgWtYdgTF1xxBNmb2IW3CZkML5nGfcRrFvNaBHd3UQEqbFKZgnIX29h5VoxekyiwFaGD-0RXL83jF7k39hytEzTatwoVjZ-frga0KFl-nLce3OwncRXVCGmxoFzUsyu9TQFS2Mm_p0AMX1y1MAX1JmLC3WFhH3BohhRqpzBtjSfs_f46nE1-HKjqZ1ERrAc2fmiVJjmG7sT702JRuuzrgUpHlMy2juBG4DkVcMlj4neJUmCD1vZyZBRggfaIxNkwUhHtmS2Cp9tOcwNu47tSg"}, // Signing algorithm PS384.
			{"eyJhbGciOiJQUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ0VzZhZTdUb21FNl8yam9vTS1zZjlOXzZsV2c3SE50YVFYckRzRWxCek00In0.eyJleHAiOjE2MTU0MDcwMDUsImlhdCI6MTYxNTQwNjk0NSwianRpIjoiYzJmMmZiMjQtOTQ1Yi00YTA4LWE3ZTQtYTZhNzRlZTIwMDFiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.d5E6m_isNWy0Y5E-udUruMbThe3NHMb7x90rzOxlrEyyhZEqjuREP97KQXIospLY41TKj3VURJbRFebg-my4R8w1-OlaciDdoWND2juk8y_vIMlgYb9lLMnS1ZI5Ayq3OQ4Bh2TXLsZwQaBWoccyVSD1qCgZsCH-ZIbxJmefkM6k99fA8QWwNFL-bD1kHELBdZfk-26JSRWiA_0WocQZcC5DWsmbslwICo2yT59X4ancvxNA-mns0Wt41-sj9sAAr-qOAubGjpPC8-FqVZXeDTiuaAqQA2K3MRKMwHMZY6e-duwCltGll_kZf2jUlwfF7LLuT7YP6p7rxCjIhHaAMw"}, // Signing algorithm PS512.
			{"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJDNjVxMEVLUXlocGQxbTRmcjdTS08ySGVfbkF4Z0N0QWR3czY0ZDJCTHQ4In0.eyJleHAiOjE2MTU0MDcwMjYsImlhdCI6MTYxNTQwNjk2NiwianRpIjoiMzg1NjE4ODItOTA5MS00ODY3LTkzYmYtMmE3YmU4NTc3YmZiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.Cmgz3aC_b_kpOmGM-_nRisgQul0d9Jg7BpMLe5F_fdryRhwhW5fQBZtz6FipQ0Tc4jggI6L3Dx1jS2kn823aWCR0x-OAFCawIXnwgAKuM1m2NL7Y6LKC07nytdB_qU4GknAl3jEG-tZIJBHQwYP-K6QKmAT9CdF1ZPbc9u8RgRCPN8UziYcOpvStiG829BO7cTzCt7tp5dJhem8_CnRWBKzelP1fs_z4fAQtW2sgyhX9SUYb5WON-4zrn4i01FlYUwZV-AC83zP6BuHIiy3XpAuTiTp2BjZ-1nzCLWBRpIm_lOObFeo-3AQqWPxzLVAmTFQMKReUF9T8ehL2Osr1XQ"}, // Signing algorithm RS256.
			{"eyJhbGciOiJSUzM4NCIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJnbm1BZnZtbHNpM2tLSDNWbE0xQUo4NVAyaGVrUThPTl9YdkpxczN4UEQ4In0.eyJleHAiOjE2MTU0MDcwNDUsImlhdCI6MTYxNTQwNjk4NSwianRpIjoiYzJiZGRhNGItMWNjNy00MzhmLWI1YzktMDk2ZDk4MTg4YWQ4IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.F-y1IULtpWICLu0lrTniJwf3x1wHSQvVJ2BmXhRm-bhEdwftJG2Ep4rg4_SZPU8CZTazqSRQE4quWw5e8m8yyVrdpAts3NDAJB6m6Up1qQvN2YBtSoGjujzRZuJ72rOGqHf0e9wUQYWsmgE4Aes0kCeOlQ0EwfTnd6qfJaqYuZj9T0KIedt7T9KBmk3ndzDQALRJ2vo12b2M2DHL6gYqokUJ4lhw9Tnm785a6Bamc_F0otAKS5e4KVFhtRzCgdZWdEXX9VfwmtZpvZYImHWFe8HnB8jqLfRhKIc5xkXE0cwiuz6eYnneSRMrM3qAPus6fbc78rIVZl7Qaxa-h1vZYQ"}, // Signing algorithm RS384.
			{"eyJhbGciOiJSUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJhcmxVeFg0aGg1NnJOTy1YZElQaERUN2JxQk1xY0J3TlF1UF9UblpKTkdzIn0.eyJleHAiOjE2MTU0MDcwNjcsImlhdCI6MTYxNTQwNzAwNywianRpIjoiYWNlNGQ5ODgtMjVjMS00NzkxLWJjZDgtNTQ3MzNiYTg0MTZiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.BHygL0iGWEL46QdcnInqgjhgtlfBN8H2BMhFAK1sZuGB6rX-FGHFav0NgnWzT5Ae6wM3KqJY30aME5OOvycV--5w7ZX8uqnYjXYdLbJ-azLtP3Hw8vwY9u6GC81ZvWZdKvQNpbcuvtJYL2uhrbv0GdXcClTHmA-NiReGFuBFgo0fBX_ipjNx_q94OnaDxSHUSGeKqNFoNOttXBV7Xqa_K9j60zfoO9E2OV0jkYI5_8MPPZI85Y8XG7PUK2opg7LHNrFbB67C_RxJ7ZDKt0jBApzJyZ96_8UBSvNtBnytQO-CexOG-5y-nN3mcw7NU7g7dFxlb18Yur194h7VTT9tHQ"}, // Signing algorithm RS512.
			{"eyJhbGciOiJSUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJhcmxVeFg0aGg1NnJOTy1YZElQaERUN2JxQk1xY0J3TlF1UF9UblpKTkdzIn0.eyJleHAiOjE2MTU0MDcwNjcsImlhdCI6MTYxNTQwNzAwNywianRpIjoiYWNlNGQ5ODgtMjVjMS00NzkxLWJjZDgtNTQ3MzNiYTg0MTZiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.BHygL0iGWEL46QdcnInqgjhgtlfBN8H2BMhFAK1sZuGB6rX-FGHFav0NgnWzT5Ae6wM3KqJY30aME5OOvycV--5w7ZX8uqnYjXYdLbJ-azLtP3Hw8vwY9u6GC81ZvWZdKvQNpbcuvtJYL2uhrbv0GdXcClTHmA-NiReGFuBFgo0fBX_ipjNx_q94OnaDxSHUSGeKqNFoNOttXBV7Xqa_K9j60zfoO9E2OV0jkYI5_8MPPZI85Y8XG7PUK2opg7LHNrFbB67C_RxJ7ZDKt0jBApzJyZ96_8UBSvNtBnytQO-CexOG-5y-nN3mcw7NU7g7dFxlb18Yur194h7VTT9tHQ"}, // RSA inter.
			{"eyJhbGciOiJFZERTQSIsImtpZCI6IlE1NkEiLCJrdHkiOiJPS1AiLCJ0eXAiOiJKV1QifQ.e30.BBUMb14EQqbhht6uR5V6_R7bQUiYtAi3v1bOvh4SO-_XA-WEs3k0OE2negGlsbIiXqcEP8pgHSB6r7JE0qUTCgiyJ_BCU7feuWyEohVW6ww7USRTMP4siphL3Xeewu0BKBg"}, // EdDSA.
			{"eyJhbGciOiJIUzI1NiIsImtpZCI6ImhtYWMiLCJrdHkiOiJvY3QiLCJ0eXAiOiJKV1QifQ.e30.vZ8H2-9j1pDXLNL2GFKbZOkC2qyA0dr7AiTJpNjgLcY"},                                                                                         // HMAC
		}

		if opts.RefreshInterval != 0 {
			time.Sleep(opts.RefreshInterval)
		}

		for _, tc := range testCases {
			t.Run(fmt.Sprintf("token: %s", tc.token), func(t *testing.T) {
				// Use the JWKS jwt.Keyfunc to parse the token.
				//
				// Don't check for general errors. Unfortunately, an error occurs when a token is expired. All hard
				// coded tokens are expired.
				_, err = jwt.Parse(tc.token, jwks.Keyfunc)
				if err != nil {
					if errors.Is(err, jwt.ErrInvalidKeyType) {
						t.Fatalf(logFmt, "Invaild key type selected.", err)
					}
				}
			})
		}

		jwks.EndBackground()
	}
}

// TestJWKS_Use tests that JWKs with a use value "enc" are not returned from jwt.Keyfunc.
func TestJWKS_Use(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(jwksJSON))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	jwksURL := server.URL
	opts := keyfunc.Options{
		JWKUseWhitelist: []keyfunc.JWKUse{keyfunc.UseOmitted, keyfunc.UseSignature},
	}
	jwks, err := keyfunc.Get(jwksURL, opts)
	if err != nil {
		t.Fatalf(logFmt, "Failed to get JWKS from testing URL.", err)
	}

	_, err = jwt.Parse(tokenUseEnc, jwks.Keyfunc)
	if !errors.Is(err, keyfunc.ErrJWKUseWhitelist) {
		t.Fatal(`Failed to return correct error for JWK with "use" parameter value of "enc".`)
	}
}

// TestJWKS_UseNoWhitelistOverride tests that JWKUseNoWhitelist option overrides the JWKUseWhitelist option.
func TestJWKS_UseNoWhitelistOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(jwksJSON))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	jwksURL := server.URL
	opts := keyfunc.Options{
		JWKUseWhitelist:   []keyfunc.JWKUse{keyfunc.UseOmitted, keyfunc.UseSignature},
		JWKUseNoWhitelist: true,
	}
	jwks, err := keyfunc.Get(jwksURL, opts)
	if err != nil {
		t.Fatalf(logFmt, "Failed to get JWKS from testing URL.", err)
	}

	_, err = jwt.Parse(tokenUseEnc, jwks.Keyfunc)
	if err != nil {
		t.Fatalf(logFmt, "The JWKUseNoWhitelist option should override the JWKUseWhitelist option.", err)
	}
}

// TestKIDs confirms the JWKS.KIDs returns the key IDs (`kid`) stored in the JWKS.
func TestJWKS_KIDs(t *testing.T) {
	jwks, err := keyfunc.NewJSON([]byte(jwksJSON))
	if err != nil {
		t.Fatalf(logFmt, "Failed to create a JWKS from JSON.", err)
	}

	expectedKIDs := []string{
		"zXew0UJ1h6Q4CCcd_9wxMzvcp5cEBifH0KWrCz2Kyxc",
		"ebJxnm9B3QDBljB5XJWEu72qx6BawDaMAhwz4aKPkQ0",
		"TVAAet63O3xy_KK6_bxVIu7Ra3_z1wlB543Fbwi5VaU",
		"arlUxX4hh56rNO-XdIPhDT7bqBMqcBwNQuP_TnZJNGs",
		"tW6ae7TomE6_2jooM-sf9N_6lWg7HNtaQXrDsElBzM4",
		"Lx1FmayP2YBtxaqS1SKJRJGiXRKnw2ov5WmYIMG-BLE",
		"gnmAfvmlsi3kKH3VlM1AJ85P2hekQ8ON_XvJqs3xPD8",
		"CGt0ZWS4Lc5faiKSdi0tU0fjCAdvGROQRGU9iR7tV0A",
		"C65q0EKQyhpd1m4fr7SKO2He_nAxgCtAdws64d2BLt8",
		"Q56A",
		"hmac",
		"kidWithBadUse",
	}

	actual := jwks.KIDs()

	actualLen := len(actual)
	expectedLen := len(expectedKIDs)
	if actualLen != expectedLen {
		t.Fatalf("The number of key IDs was not as expected.\n  Expected length: %d\n  Actual length: %d\n  Actual key IDs: %v", expectedLen, actualLen, actual)
	}

	for _, expectedKID := range expectedKIDs {
		found := false
		for _, kid := range actual {
			if kid == expectedKID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Failed to find expected key ID in the slice of key IDs in the JWKS.\n  Missing: %s", expectedKID)
		}
	}
}

// TestJWKS_Len confirms the JWKS.Len returns the number of keys in the JWKS.
func TestJWKS_Len(t *testing.T) {
	jwks, err := keyfunc.NewJSON([]byte(jwksJSON))
	if err != nil {
		t.Fatalf(logFmt, "Failed to create a JWKS from JSON.", err)
	}

	expectedKIDs := []string{
		"zXew0UJ1h6Q4CCcd_9wxMzvcp5cEBifH0KWrCz2Kyxc",
		"ebJxnm9B3QDBljB5XJWEu72qx6BawDaMAhwz4aKPkQ0",
		"TVAAet63O3xy_KK6_bxVIu7Ra3_z1wlB543Fbwi5VaU",
		"arlUxX4hh56rNO-XdIPhDT7bqBMqcBwNQuP_TnZJNGs",
		"tW6ae7TomE6_2jooM-sf9N_6lWg7HNtaQXrDsElBzM4",
		"Lx1FmayP2YBtxaqS1SKJRJGiXRKnw2ov5WmYIMG-BLE",
		"gnmAfvmlsi3kKH3VlM1AJ85P2hekQ8ON_XvJqs3xPD8",
		"CGt0ZWS4Lc5faiKSdi0tU0fjCAdvGROQRGU9iR7tV0A",
		"C65q0EKQyhpd1m4fr7SKO2He_nAxgCtAdws64d2BLt8",
		"Q56A",
		"hmac",
		"WW91IGdldCBhIGdvbGQgc3RhciDwn4yfCg",
	}

	actualLen := jwks.Len()
	expectedLen := len(expectedKIDs)
	if actualLen != expectedLen {
		t.Fatalf("The number of key IDs was not as expected.\n  Expected length: %d\n  Actual length: %d\n", expectedLen, actualLen)
	}
}

// TestRateLimit performs a test to confirm the rate limiter works as expected.
func TestRateLimit(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "*")
	if err != nil {
		t.Fatalf(logFmt, "Failed to create a temporary directory.", err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Fatalf(logFmt, "Failed to remove temporary directory.", err)
		}
	}()

	refreshes := uint(0)
	refreshMux := sync.Mutex{}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		refreshMux.Lock()
		refreshes++
		refreshMux.Unlock()

		writer.WriteHeader(200)
		if _, serveErr := writer.Write([]byte(jwksJSON)); serveErr != nil {
			t.Errorf(logFmt, "Failed to serve JWKS.", err)
		}
	}))
	defer server.Close()

	jwksURL := server.URL + jwksFilePath

	refreshInterval := time.Second
	refreshRateLimit := time.Millisecond * 500
	refreshTimeout := time.Second
	options := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			t.Errorf(logFmt, "The package itself had an error.", err)
		},
		RefreshInterval:   refreshInterval,
		RefreshRateLimit:  refreshRateLimit,
		RefreshTimeout:    refreshTimeout,
		RefreshUnknownKID: true,
	}

	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		t.Fatalf(logFmt, "Failed to create *keyfunc.JWKS.", err)
	}
	defer jwks.EndBackground()

	// Create four JWTs with unknown kids.
	//
	// These should prompt two refreshes.
	// The first one will not be rate limited.
	// The second will get a rate limit queue.
	// The third will get no rate limit queue and will be ignored because there is already a one in the queue.
	// The fourth will get no rate limit queue and will be ignored because there is already a one in the queue.
	token1 := "eyJraWQiOiI0NWU3ZDcyMiIsInR5cCI6IkpXVCIsImFsZyI6IlJTNTEyIn0.eyJzdWIiOiJBbmRyZWEiLCJhdWQiOiJUYXNodWFuIiwiaXNzIjoiandrcy1zZXJ2aWNlLmFwcHNwb3QuY29tIiwiZXhwIjoxNjI0NzU2OTAwLCJpYXQiOjE2MjQ3NTY4OTUsImp0aSI6IjA5ZjkzZjljLTU0ZjMtNDM5Yi04Njg2LWZhMGYwMjlmYmIwZSJ9.g643vWnvDvR5u5TeCUaCblp-Ss8SPWoZrOxBo3y6WP9xQnRW63VSbacCirl-5nGRPoX6vostZAkRyUl62ICQHpTj3bRnDY4ZbkcQ42xtrWMBsI2Sw6dAmZtGsCR_tguQZmvdKE4gVNnFWLp0hBjCeLxPVbc59vC6njMdz7XHcOdW7RXN6iUYjLFoPAr4Qg93Vbrwfo9Qmkm8bDgbnuoJ3aQq0RFa02G1KC2-cx8SuUbxso_Uu7ddY6HDRL5OPF3xS9cKO5ty4zCfGYIVDhfH7V-zA2cJZyA2dlv3Ddd-ntU42aud0M4PcTTdjHf1CE29sCZHk5wTRgxsTjfWglYQQiVQJEkw6DD6kTlQ_MwN4p_OWNj06b55mXM6Bj9c9y8TfPLETDy_PRc1lHu1PuiizLg019JaGidpTLF8IdKTa9emkEnf2n8xWi-YMkkRk57hpuc56GmnBR0d8ODfuL0XILlQp2guFsVRo9A4Sdqy7fGdZGoSS4XzSR-TIEw7W_KSqlYCtWC0xNk1Kze3xSY2mDqrn1YFFlvXgXQlgzU8GN1eL7QRRQlxaPGti2wEH6OYH4A160nR_OM-zFBobpQn79g8HsK8yZgPiY0p94F6pvKBQtSHDBvAe3W0-UHYfspwT9cQGVgqCGol6A8XNeBlVQpko9ves4UgCRSb6o9u_p4"
	token2 := "eyJraWQiOiIyYTFkODRhMCIsInR5cCI6IkpXVCIsImFsZyI6IkVTMzg0In0.eyJzdWIiOiJBbmRyZWEiLCJhdWQiOiJUYXNodWFuIiwiaXNzIjoiandrcy1zZXJ2aWNlLmFwcHNwb3QuY29tIiwiZXhwIjoxNjI0NzU3MjExLCJpYXQiOjE2MjQ3NTcyMDYsImp0aSI6ImU4YjQ1YmIwLTczZjgtNDkzNi04MjQxLWE1OGFlZWMyZWE2NCJ9.6Isd4unU2TAmRB1SouaHBV9LUjFGIuhOrxkQlDjh6qKRgb7UsiPtQm87S2qrriLaFjyCmrmU6cDpVBpTOutjPxweIqT-1EfsS-dkENIVWPVgQ5-KuNu2jXyGYpPeFBUA"
	token3 := "eyJraWQiOiIxZjEyOGFkZSIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2In0.eyJzdWIiOiJSZWJlY2NhIiwiYXVkIjoiQWxpY2UiLCJpc3MiOiJqd2tzLXNlcnZpY2UuYXBwc3BvdC5jb20iLCJleHAiOjE2MjQ3NTkzODIsImlhdCI6MTYyNDc1OTM3NywianRpIjoiMzU2MWY4MDctNDRkNi00OWE5LWFlYWItMmQ1MjQ2YWYxNDhlIn0.5eZbJlvnaFsRwPhBHmXljp9vgsrB0Q9d3dSz4va29ahTKsFGFo8tYy0e69ehqSb-dbFy9azRRtygwwtYuaEFuA"
	token4 := "eyJraWQiOiIyZDQ3NjUwYSIsInR5cCI6IkpXVCIsImFsZyI6IlBTMzg0In0.eyJzdWIiOiJGcmVkYSIsImF1ZCI6Ikx1Y2lhIiwiaXNzIjoiandrcy1zZXJ2aWNlLmFwcHNwb3QuY29tIiwiZXhwIjoxNjI0ODA0MTk0LCJpYXQiOjE2MjQ4MDQxODksImp0aSI6IjdjNTQ2Y2RmLTYwMTEtNDI3Ny04Y2Q0LTMwNjZmZTYwNTExZSJ9.hQm-OP_MMk8_S13-ohiINRuDP2IlCiB3yn8Ov6qTjeFbq4gZ6MegeJH_qiZOvXqlzOAwpwd5P4nm5JeS6LlNGdW6V_agwYwnAd08GI7APQNRib692_sEk1DKdSk-S-Y8V_ZAgeTT8asdaSDw4EBPxkDvROcuEqesZrfqnrOcpdqqa2BcmwX8q5sLtQ8TMp4cOvEZg-J8_0j2kdCUkv_n9ZdsRoA3EUT8M1bYqnGRRxIRqflsm-S_xq3HxMAnPF5hPlqIKFVKuRsU0SKgcHZGwXpuK2lJqPobl6MI987tGrc9sPPFzVkNYxeltcxu34-ZjzN6iCQN8r0w-mfqCZav7A"

	// Use the JWKS jwk.Keyfunc to parse the tokens signed with unknown kids at nearly the same time.
	waitGroup := sync.WaitGroup{}
	waitGroup.Add(3)
	go func() {
		defer waitGroup.Done()
		if _, parseErr := jwt.Parse(token1, jwks.Keyfunc); parseErr != nil {
			if errors.Is(parseErr, jwt.ErrInvalidKeyType) {
				t.Errorf(logFmt, "Invaild key type selected.", parseErr)
			}
		}
	}()
	go func() {
		defer waitGroup.Done()
		if _, parseErr := jwt.Parse(token2, jwks.Keyfunc); parseErr != nil {
			if errors.Is(parseErr, jwt.ErrInvalidKeyType) {
				t.Errorf(logFmt, "Invaild key type selected.", parseErr)
			}
		}
	}()
	go func() {
		defer waitGroup.Done()
		if _, parseErr := jwt.Parse(token3, jwks.Keyfunc); parseErr != nil {
			if errors.Is(parseErr, jwt.ErrInvalidKeyType) {
				t.Errorf(logFmt, "Invaild key type selected.", parseErr)
			}
		}
	}()
	if _, parseErr := jwt.Parse(token4, jwks.Keyfunc); parseErr != nil {
		if errors.Is(parseErr, jwt.ErrInvalidKeyType) {
			t.Fatalf(logFmt, "Invaild key type selected.", parseErr)
		}
	}
	waitGroup.Wait()

	// Confirm the JWKS was only refreshed once. (Refresh counter was first incremented on the creation of the JWKS.)
	refreshMux.Lock()
	expected := uint(2)
	if refreshes != expected {
		t.Fatalf("An incorrect number of refreshes occurred.\n  Expected: %d\n  Got: %d\n", expected, refreshes)
	}
	refreshMux.Unlock()

	// Wait for the rate limiter to take the next queue.
	time.Sleep(refreshRateLimit + time.Millisecond*100)
	refreshMux.Lock()
	expected = uint(3)
	if refreshes != expected {
		t.Fatalf("An incorrect number of refreshes occurred.\n  Expected: %d\n  Got: %d\n", expected, refreshes)
	}
	refreshMux.Unlock()

	// Wait for the refresh interval to occur.
	time.Sleep(refreshInterval + time.Millisecond*100)
	refreshMux.Lock()
	expected = uint(4)
	if refreshes != expected {
		t.Fatalf("An incorrect number of refreshes occurred.\n  Expected: %d\n  Got: %d\n", expected, refreshes)
	}
	refreshMux.Unlock()
}

// TestRawJWKS confirms a copy of the raw JWKS is returned from the method.
func TestRawJWKS(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "*")
	if err != nil {
		t.Fatalf(logFmt, "Failed to create a temporary directory.", err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Fatalf(logFmt, "Failed to remove temporary directory.", err)
		}
	}()

	jwksFile := filepath.Join(tempDir, jwksFilePath)

	err = os.WriteFile(jwksFile, []byte(jwksJSON), 0600)
	if err != nil {
		t.Fatalf(logFmt, "Failed to write JWKS file to temporary directory.", err)
	}

	server := httptest.NewServer(http.FileServer(http.Dir(tempDir)))
	defer server.Close()

	jwksURL := server.URL + jwksFilePath

	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{})
	if err != nil {
		t.Fatalf(logFmt, "Failed to get JWKS from testing URL.", err)
	}

	raw := jwks.RawJWKS()
	if !bytes.Equal(raw, []byte(jwksJSON)) {
		t.Fatalf("Raw JWKS does not match remote JWKS resource.")
	}

	// Overwrite the slice returned, if it's a copy, it should ruin the original.
	emptySlice := make([]byte, len(raw))
	copy(raw, emptySlice)

	nextRaw := jwks.RawJWKS()
	if bytes.Equal(nextRaw, emptySlice) {
		t.Fatalf("Raw JWKS is not a copy.")
	}
}

// TestRequestFactory confirms the behavior of request factories.
func TestRequestFactory(t *testing.T) {
	var fullJWKSHandler http.Handler
	{
		tempDir, err := os.MkdirTemp("", "*")
		if err != nil {
			t.Fatalf(logFmt, "Failed to create a temporary directory.", err)
		}
		defer func() {
			err = os.RemoveAll(tempDir)
			if err != nil {
				t.Fatalf(logFmt, "Failed to remove temporary directory.", err)
			}
		}()

		jwksFile := filepath.Join(tempDir, jwksFilePath)

		err = os.WriteFile(jwksFile, []byte(jwksJSON), 0600)
		if err != nil {
			t.Fatalf(logFmt, "Failed to write JWKS file to temporary directory.", err)
		}

		fullJWKSHandler = http.FileServer(http.Dir(tempDir))
	}
	var emptyJWKSHandler http.Handler
	{
		tempDir, err := os.MkdirTemp("", "*")
		if err != nil {
			t.Fatalf(logFmt, "Failed to create a temporary directory.", err)
		}
		defer func() {
			err = os.RemoveAll(tempDir)
			if err != nil {
				t.Fatalf(logFmt, "Failed to remove temporary directory.", err)
			}
		}()

		jwksFile := filepath.Join(tempDir, jwksFilePath)

		err = os.WriteFile(jwksFile, []byte(emptyJWKSJSON), 0600)
		if err != nil {
			t.Fatalf(logFmt, "Failed to write JWKS file to temporary directory.", err)
		}

		emptyJWKSHandler = http.FileServer(http.Dir(tempDir))
	}

	const (
		fullJWKSUserAgent = "full-jwks-please"
		userAgentHeader   = "User-Agent"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get(userAgentHeader) {
		case fullJWKSUserAgent:
			fullJWKSHandler.ServeHTTP(w, r)
		default:
			emptyJWKSHandler.ServeHTTP(w, r)
		}
	}))
	defer server.Close()

	jwksURL := server.URL + jwksFilePath

	optsFail := keyfunc.Options{
		RequestFactory: func(ctx context.Context, url string) (*http.Request, error) {
			badURL := fmt.Sprintf("%s/does/not/exist", url)
			return http.NewRequestWithContext(ctx, http.MethodGet, badURL, bytes.NewReader(nil))
		},
	}

	_, err := keyfunc.Get(jwksURL, optsFail)
	if err == nil {
		t.Fatalf("Creation of *keyfunc.JWKS reading from bad URL must fail.")
	}

	optsSuccess := keyfunc.Options{
		RequestFactory: func(ctx context.Context, url string) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodGet, url, bytes.NewReader(nil))
		},
	}

	jwks, err := keyfunc.Get(jwksURL, optsSuccess)
	if err != nil {
		t.Fatalf(logFmt, "Failed to get JWKS from testing URL.", err)
	}

	if len(jwks.ReadOnlyKeys()) != 0 {
		t.Fatalf("JWKS should be empty due to lack of custom HTTP header.")
	}

	optsCustomHeader := keyfunc.Options{
		RequestFactory: func(ctx context.Context, url string) (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, bytes.NewReader(nil))
			if err != nil {
				return nil, fmt.Errorf("failed to create request: %w", err)
			}
			req.Header.Set(userAgentHeader, fullJWKSUserAgent)
			return req, nil
		},
	}

	jwks, err = keyfunc.Get(jwksURL, optsCustomHeader)
	if err != nil {
		t.Fatalf(logFmt, "Failed to get JWKS from testing URL.", err)
	}

	if len(jwks.ReadOnlyKeys()) == 0 {
		t.Fatalf("JWKS should not be empty due to custom HTTP header.")
	}
}

// TestUnknownKIDRefresh performs a test to confirm that an Unknown kid with refresh the JWKS.
func TestUnknownKIDRefresh(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "*")
	if err != nil {
		t.Fatalf(logFmt, "Failed to create a temporary directory.", err)
	}
	defer func() {
		err = os.RemoveAll(tempDir)
		if err != nil {
			t.Fatalf(logFmt, "Failed to remove temporary directory.", err)
		}
	}()

	jwksFile := filepath.Join(tempDir, strings.TrimPrefix(jwksFilePath, "/"))

	err = os.WriteFile(jwksFile, []byte(emptyJWKSJSON), 0600)
	if err != nil {
		t.Fatalf(logFmt, "Failed to write JWKS file to temporary directory.", err)
	}

	server := httptest.NewServer(http.FileServer(http.Dir(tempDir)))
	defer server.Close()

	testingRefreshErrorHandler := func(err error) {
		t.Fatalf(logFmt, "Unhandled JWKS error.", err)
	}

	jwksURL := server.URL + jwksFilePath

	options := keyfunc.Options{
		RefreshErrorHandler: testingRefreshErrorHandler,
		RefreshUnknownKID:   true,
	}

	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		t.Fatalf(logFmt, "Failed to create *keyfunc.JWKS.", err)
	}
	defer jwks.EndBackground()

	err = os.WriteFile(jwksFile, []byte(jwksJSON), 0600)
	if err != nil {
		t.Fatalf(logFmt, "Failed to write JWKS file to temporary directory.", err)
	}

	// Use any JWT signed by a key in the non-empty JWKS.
	token := "eyJhbGciOiJFUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJDR3QwWldTNExjNWZhaUtTZGkwdFUwZmpDQWR2R1JPUVJHVTlpUjd0VjBBIn0.eyJleHAiOjE2MTU0MDY4NjEsImlhdCI6MTYxNTQwNjgwMSwianRpIjoiYWVmOWQ5YjItN2EyYy00ZmQ4LTk4MzktODRiMzQ0Y2VmYzZhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.iQ77QGoPDNjR2oWLu3zT851mswP8J-h_nrGhs3fpa_tFB3FT1deKPGkjef9JOTYFI-CIVxdCFtW3KODOaw9Nrw"

	// Use the JWKS jwk.Keyfunc to parse the token.
	//
	// Don't check for general errors. Unfortunately, an error occurs when a token is expired. All hard
	// coded tokens are expired.
	_, err = jwt.Parse(token, jwks.Keyfunc)
	if err != nil {
		if errors.Is(err, jwt.ErrInvalidKeyType) {
			t.Fatalf(logFmt, "Invaild key type selected.", err)
		}
	}
}

// TestReadOnlyKeys verifies that the .ReadOnlyKeys() method returns a map with the correct types.
func TestReadOnlyKeys(t *testing.T) {
	jwks, err := keyfunc.NewJSON([]byte(jwksJSON))
	if err != nil {
		t.Fatalf(logFmt, "Failed to create a JWKS from JSON.", err)
	}

	for _, key := range jwks.ReadOnlyKeys() {
		switch key.(type) {
		case *rsa.PublicKey:
			// Do nothing.
		case *ecdsa.PublicKey:
			// Do nothing.
		case ed25519.PublicKey:
			// Do nothing.
		case []byte:
			// Do nothing.
		default:
			t.Errorf("Invalid type %T in .ReadOnlyKeys() method.", key)
		}
	}
}
