package keyfunc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc"
)

func TestJWKS_Refresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var counter uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddUint64(&counter, 1)
		_, err := w.Write([]byte(jwksJSON))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	jwksURL := server.URL
	opts := keyfunc.Options{
		Ctx: ctx,
	}
	jwks, err := keyfunc.Get(jwksURL, opts)
	if err != nil {
		t.Fatalf(logFmt, "Failed to get JWKS from testing URL.", err)
	}

	err = jwks.Refresh(ctx, keyfunc.RefreshOptions{IgnoreRateLimit: true})
	if err != nil {
		t.Fatalf(logFmt, "Failed to refresh JWKS.", err)
	}

	count := atomic.LoadUint64(&counter)
	if count != 2 {
		t.Fatalf("Expected 2 refreshes, got %d.", count)
	}
}

func TestJWKS_RefreshUsingBackgroundGoroutine(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var counter uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddUint64(&counter, 1)
		_, err := w.Write([]byte(jwksJSON))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	jwksURL := server.URL
	opts := keyfunc.Options{
		Ctx:              ctx,
		RefreshInterval:  time.Hour,
		RefreshRateLimit: time.Hour,
	}
	jwks, err := keyfunc.Get(jwksURL, opts)
	if err != nil {
		t.Fatalf(logFmt, "Failed to get JWKS from testing URL.", err)
	}

	err = jwks.Refresh(ctx, keyfunc.RefreshOptions{IgnoreRateLimit: true})
	if err != nil {
		t.Fatalf(logFmt, "Failed to refresh JWKS.", err)
	}

	count := atomic.LoadUint64(&counter)
	if count != 2 {
		t.Fatalf("Expected 2 refreshes, got %d.", count)
	}
}
