package keyfunc_test

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/MicahParks/keyfunc/v2"
)

func TestResponseExtractorStatusOK(t *testing.T) {
	var mux sync.Mutex
	statusCode := http.StatusOK

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mux.Lock()
		writer.WriteHeader(statusCode)
		mux.Unlock()
		_, _ = writer.Write([]byte(jwksJSON))
	}))
	defer server.Close()

	options := keyfunc.Options{
		ResponseExtractor: keyfunc.ResponseExtractorStatusOK,
	}
	jwks, err := keyfunc.Get(server.URL, options)
	if err != nil {
		t.Fatalf("Failed to get JWK Set from server.\nError: %s", err)
	}

	if len(jwks.ReadOnlyKeys()) == 0 {
		t.Fatalf("Expected JWK Set to have keys.")
	}

	mux.Lock()
	statusCode = http.StatusInternalServerError
	mux.Unlock()

	_, err = keyfunc.Get(server.URL, options)
	if !errors.Is(err, keyfunc.ErrInvalidHTTPStatusCode) {
		t.Fatalf("Expected error to be ErrInvalidHTTPStatusCode.\nError: %s", err)
	}
}

func TestResponseExtractorStatusAny(t *testing.T) {
	var mux sync.Mutex
	statusCode := http.StatusOK

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mux.Lock()
		writer.WriteHeader(statusCode)
		mux.Unlock()
		_, _ = writer.Write([]byte(jwksJSON))
	}))
	defer server.Close()

	options := keyfunc.Options{
		ResponseExtractor: keyfunc.ResponseExtractorStatusAny,
	}
	jwks, err := keyfunc.Get(server.URL, options)
	if err != nil {
		t.Fatalf("Failed to get JWK Set from server.\nError: %s", err)
	}

	if len(jwks.ReadOnlyKeys()) == 0 {
		t.Fatalf("Expected JWK Set to have keys.")
	}

	mux.Lock()
	statusCode = http.StatusInternalServerError
	mux.Unlock()

	_, err = keyfunc.Get(server.URL, options)
	if err != nil {
		t.Fatalf("Expected error no error for 500 status code.\nError: %s", err)
	}
}

func TestTolerateStartupFailure(t *testing.T) {
	var mux sync.Mutex
	shouldError := true

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mux.Lock()
		defer mux.Unlock()
		if shouldError {
			writer.WriteHeader(http.StatusInternalServerError)
		} else {
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(jwksJSON))
		}
	}))
	defer server.Close()

	options := keyfunc.Options{
		TolerateInitialJWKHTTPError: true,
		RefreshUnknownKID:           true,
	}
	jwks, err := keyfunc.Get(server.URL, options)
	if err != nil {
		t.Fatalf("TolerateInitialJWKHTTPError should not return error on bad HTTP startup.\nError: %s", err)
	}

	if len(jwks.ReadOnlyKeys()) != 0 {
		t.Fatalf("Expected JWK Set to have no keys.")
	}

	const token = "eyJhbGciOiJFUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJDR3QwWldTNExjNWZhaUtTZGkwdFUwZmpDQWR2R1JPUVJHVTlpUjd0VjBBIn0.eyJleHAiOjE2MTU0MDY4NjEsImlhdCI6MTYxNTQwNjgwMSwianRpIjoiYWVmOWQ5YjItN2EyYy00ZmQ4LTk4MzktODRiMzQ0Y2VmYzZhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.iQ77QGoPDNjR2oWLu3zT851mswP8J-h_nrGhs3fpa_tFB3FT1deKPGkjef9JOTYFI-CIVxdCFtW3KODOaw9Nrw"
	_, err = jwt.Parse(token, jwks.Keyfunc)
	if !errors.Is(err, keyfunc.ErrKIDNotFound) {
		t.Fatalf("Expected error to be ErrKIDNotFound.\nError: %s", err)
	}

	mux.Lock()
	shouldError = false
	mux.Unlock()

	_, err = jwt.Parse(token, jwks.Keyfunc)
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("Expected error to be jwt.ErrTokenExpired.\nError: %s", err)
	}

	if len(jwks.ReadOnlyKeys()) == 0 {
		t.Fatalf("Expected JWK Set to have keys.")
	}
}
