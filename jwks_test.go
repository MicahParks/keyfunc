package keyfunc_test

import (
	"embed"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/MicahParks/keyfunc"
)

// exampleJWKS is an example JWKS with every supported key algorithm.
//go:embed example_jwks.json
var exampleJWKS embed.FS // TODO Make this not here because not everyone is on go 1.16?

// TestJWKS performs a table test on the JWKS code.
func TestJWKS(t *testing.T) {

	// Could add a test with an invalid JWKS endpoint.

	// Create the testing HTTP server that hosts a JWKS endpoint at /example_jwks.json.
	server := httptest.NewServer(http.FileServer(http.FS(exampleJWKS)))
	defer server.Close()

	// Create testing options.
	testingRefreshInterval := time.Millisecond * 500
	testingRefreshTimeout := time.Second
	testingRefreshErrorHandler := func(err error) {
		t.Errorf("unhandled JWKS error: %s", err.Error())
	}

	// Set the JWKS URL.
	jwksURL := server.URL + "/example_jwks.json"

	// Create a table of options to test.
	options := []keyfunc.Options{
		{}, // Default options.
		{
			Client: http.DefaultClient, // Should be ineffectual. Just for code coverage.
		},
		{
			RefreshInterval: &testingRefreshInterval,
		},
		{
			RefreshTimeout: &testingRefreshTimeout,
		},
		{
			RefreshErrorHandler: testingRefreshErrorHandler,
		},
	}

	// Iterate through all options.
	for _, opts := range options {

		// Create the JWKS from the resource at the testing URL.
		jwks, err := keyfunc.Get(jwksURL, opts)
		if err != nil {
			t.Errorf("Failed to get JWKS from testing URL.\nError: %s", err.Error())
			t.FailNow()
		}

		// Create the test cases.
		testCases := []struct {
			token string
		}{
			{""}, // Empty JWT.
			{"eyJhbGciOiJFUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJDR3QwWldTNExjNWZhaUtTZGkwdFUwZmpDQWR2R1JPUVJHVTlpUjd0VjBBIn0.eyJleHAiOjE2MTU0MDY4NjEsImlhdCI6MTYxNTQwNjgwMSwianRpIjoiYWVmOWQ5YjItN2EyYy00ZmQ4LTk4MzktODRiMzQ0Y2VmYzZhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.iQ77QGoPDNjR2oWLu3zT851mswP8J-h_nrGhs3fpa_tFB3FT1deKPGkjef9JOTYFI-CIVxdCFtW3KODOaw9Nrw"},                                                                                                                                                                                                                                                                 // Signing algorithm ES256.
			{"eyJhbGciOiJFUzM4NCIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUVkFBZXQ2M08zeHlfS0s2X2J4Vkl1N1JhM196MXdsQjU0M0Zid2k1VmFVIn0.eyJleHAiOjE2MTU0MDY4OTAsImlhdCI6MTYxNTQwNjgzMCwianRpIjoiYWNhNDU4NTItZTE0ZS00MjgxLTljZTQtN2ZiNzVkMTg1MWJmIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.oHFT-RvbNNT6p4_tIoZzr4IS88bZqy20cJhF6FZCIXALZ2dppoOjutanPVxzuLC5axG3P71noVghNUF8X44bTShP1boLrlde2QKmj5GxDR-oNEb9ES_zC10rZ5I76CwR"},                                                                                                                                                                                                                       // Signing algorithm ES384.
			{"eyJhbGciOiJFUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJlYkp4bm05QjNRREJsakI1WEpXRXU3MnF4NkJhd0RhTUFod3o0YUtQa1EwIn0.eyJleHAiOjE2MTU0MDY5MDksImlhdCI6MTYxNTQwNjg0OSwianRpIjoiMjBhMGI1MTMtN2E4My00OGQ2LThmNDgtZmQ3NDc1N2Y4OWRiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.AdR59BCvGlctL5BMgXlpJBBToKTPG4SVa-oJKBqE7qxvTSBwAQM5D3uUc2toM3NAUERSMKOLTJfzfxenNRixrDMnAcrdFHgEY10vsDp6uqA7NMUevHE5f7jiAVK1talXS9O41IEnR2DKbAG0GgjIA2WHLhUgftG2uNN8LMKI2QSbLCfM"},                                                                                                                                                                       // Signing algorithm ES512.
			{"eyJhbGciOiJQUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ6WGV3MFVKMWg2UTRDQ2NkXzl3eE16dmNwNWNFQmlmSDBLV3JDejJLeXhjIn0.eyJleHAiOjE2MTU0MDY5NjIsImlhdCI6MTYxNTQwNjkwMiwianRpIjoiNWIyZGY5N2EtNDQyOS00ZTA0LWFkMzgtOWZmNjVlZDU2MTZjIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.tafkUwLXm3lyyqJHwAGwFPN3IO0rCrESJnVcIuI1KHPSKogn5DgWqR3B9QCvqIusqlxhGW7MvOhG-9dIy62ciKGQFDRFA9T46TMm9t8O80TnhYTB8ImX90xYuf6E74k1RiqRVcubFWKHWlhKjqXMM4dD2l8VwqL45E6kHpNDvzvILKAfrMgm0vHsfi6v5rf32HLp6Ox1PvpKrM1kDgsdXm6scgAGJCTbOQB2Pzc-i8cyFPeuckbeL4zbM3-Odqc-eI-3pXevMzUB608J3fRpQK1W053kU7iG9RFC-5nBwvrBlN4Lff_X1R3JBLkFcA0wJeFYtIFnMm6lVbA7nwa0Xg"}, // Signing algorithm PS256.
			{"eyJhbGciOiJQUzM4NCIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJMeDFGbWF5UDJZQnR4YXFTMVNLSlJKR2lYUktudzJvdjVXbVlJTUctQkxFIn0.eyJleHAiOjE2MTU0MDY5ODIsImlhdCI6MTYxNTQwNjkyMiwianRpIjoiMGY2NGJjYTktYjU4OC00MWFhLWFkNDEtMmFmZDM2OGRmNTFkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.Rxrq41AxbWKIQHWv-Tkb7rqwel3sKT_R_AGvn9mPIHqhw1m7nsQWcL9t2a_8MI2hCwgWtYdgTF1xxBNmb2IW3CZkML5nGfcRrFvNaBHd3UQEqbFKZgnIX29h5VoxekyiwFaGD-0RXL83jF7k39hytEzTatwoVjZ-frga0KFl-nLce3OwncRXVCGmxoFzUsyu9TQFS2Mm_p0AMX1y1MAX1JmLC3WFhH3BohhRqpzBtjSfs_f46nE1-HKjqZ1ERrAc2fmiVJjmG7sT702JRuuzrgUpHlMy2juBG4DkVcMlj4neJUmCD1vZyZBRggfaIxNkwUhHtmS2Cp9tOcwNu47tSg"}, // Signing algorithm PS384.
			{"eyJhbGciOiJQUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ0VzZhZTdUb21FNl8yam9vTS1zZjlOXzZsV2c3SE50YVFYckRzRWxCek00In0.eyJleHAiOjE2MTU0MDcwMDUsImlhdCI6MTYxNTQwNjk0NSwianRpIjoiYzJmMmZiMjQtOTQ1Yi00YTA4LWE3ZTQtYTZhNzRlZTIwMDFiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.d5E6m_isNWy0Y5E-udUruMbThe3NHMb7x90rzOxlrEyyhZEqjuREP97KQXIospLY41TKj3VURJbRFebg-my4R8w1-OlaciDdoWND2juk8y_vIMlgYb9lLMnS1ZI5Ayq3OQ4Bh2TXLsZwQaBWoccyVSD1qCgZsCH-ZIbxJmefkM6k99fA8QWwNFL-bD1kHELBdZfk-26JSRWiA_0WocQZcC5DWsmbslwICo2yT59X4ancvxNA-mns0Wt41-sj9sAAr-qOAubGjpPC8-FqVZXeDTiuaAqQA2K3MRKMwHMZY6e-duwCltGll_kZf2jUlwfF7LLuT7YP6p7rxCjIhHaAMw"}, // Signing algorithm PS512.
			{"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJDNjVxMEVLUXlocGQxbTRmcjdTS08ySGVfbkF4Z0N0QWR3czY0ZDJCTHQ4In0.eyJleHAiOjE2MTU0MDcwMjYsImlhdCI6MTYxNTQwNjk2NiwianRpIjoiMzg1NjE4ODItOTA5MS00ODY3LTkzYmYtMmE3YmU4NTc3YmZiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.Cmgz3aC_b_kpOmGM-_nRisgQul0d9Jg7BpMLe5F_fdryRhwhW5fQBZtz6FipQ0Tc4jggI6L3Dx1jS2kn823aWCR0x-OAFCawIXnwgAKuM1m2NL7Y6LKC07nytdB_qU4GknAl3jEG-tZIJBHQwYP-K6QKmAT9CdF1ZPbc9u8RgRCPN8UziYcOpvStiG829BO7cTzCt7tp5dJhem8_CnRWBKzelP1fs_z4fAQtW2sgyhX9SUYb5WON-4zrn4i01FlYUwZV-AC83zP6BuHIiy3XpAuTiTp2BjZ-1nzCLWBRpIm_lOObFeo-3AQqWPxzLVAmTFQMKReUF9T8ehL2Osr1XQ"}, // Signing algorithm RS256.
			{"eyJhbGciOiJSUzM4NCIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJnbm1BZnZtbHNpM2tLSDNWbE0xQUo4NVAyaGVrUThPTl9YdkpxczN4UEQ4In0.eyJleHAiOjE2MTU0MDcwNDUsImlhdCI6MTYxNTQwNjk4NSwianRpIjoiYzJiZGRhNGItMWNjNy00MzhmLWI1YzktMDk2ZDk4MTg4YWQ4IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.F-y1IULtpWICLu0lrTniJwf3x1wHSQvVJ2BmXhRm-bhEdwftJG2Ep4rg4_SZPU8CZTazqSRQE4quWw5e8m8yyVrdpAts3NDAJB6m6Up1qQvN2YBtSoGjujzRZuJ72rOGqHf0e9wUQYWsmgE4Aes0kCeOlQ0EwfTnd6qfJaqYuZj9T0KIedt7T9KBmk3ndzDQALRJ2vo12b2M2DHL6gYqokUJ4lhw9Tnm785a6Bamc_F0otAKS5e4KVFhtRzCgdZWdEXX9VfwmtZpvZYImHWFe8HnB8jqLfRhKIc5xkXE0cwiuz6eYnneSRMrM3qAPus6fbc78rIVZl7Qaxa-h1vZYQ"}, // Signing algorithm RS384.
			{"eyJhbGciOiJSUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJhcmxVeFg0aGg1NnJOTy1YZElQaERUN2JxQk1xY0J3TlF1UF9UblpKTkdzIn0.eyJleHAiOjE2MTU0MDcwNjcsImlhdCI6MTYxNTQwNzAwNywianRpIjoiYWNlNGQ5ODgtMjVjMS00NzkxLWJjZDgtNTQ3MzNiYTg0MTZiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.BHygL0iGWEL46QdcnInqgjhgtlfBN8H2BMhFAK1sZuGB6rX-FGHFav0NgnWzT5Ae6wM3KqJY30aME5OOvycV--5w7ZX8uqnYjXYdLbJ-azLtP3Hw8vwY9u6GC81ZvWZdKvQNpbcuvtJYL2uhrbv0GdXcClTHmA-NiReGFuBFgo0fBX_ipjNx_q94OnaDxSHUSGeKqNFoNOttXBV7Xqa_K9j60zfoO9E2OV0jkYI5_8MPPZI85Y8XG7PUK2opg7LHNrFbB67C_RxJ7ZDKt0jBApzJyZ96_8UBSvNtBnytQO-CexOG-5y-nN3mcw7NU7g7dFxlb18Yur194h7VTT9tHQ"}, // Signing algorithm RS512.
			// TODO Add one with missing KeyID.
		}

		// Wait for the interval to pass, if required.
		//
		// TODO Put this inside the inner table loop?
		if opts.RefreshInterval != nil {
			time.Sleep(*opts.RefreshInterval)
		}

		// Iterate through the test cases.
		for _, tc := range testCases {

			t.Run(fmt.Sprintf("token: %s", tc.token), func(t *testing.T) {

				// Use the JWKS jwk.KeyFunc to parse the token.
				//
				// Don't check for general errors. Unfortunately, an error occurs when a token is expired. All hard
				// coded tokens are expired.
				if _, err := jwt.Parse(tc.token, jwks.KeyFunc()); err != nil {
					if errors.Is(err, jwt.ErrInvalidKeyType) {
						t.Errorf("Invaild key type selected.\nError: %s", err.Error())
						t.FailNow()
					}
				}
			})
		}

		// End the background goroutine. Ineffectual without refresh interval.
		jwks.EndBackground()
	}
}
