package keyfunc_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/MicahParks/keyfunc"
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
