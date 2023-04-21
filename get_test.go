package keyfunc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v2"
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

func TestJWKS_RefreshCancelCtx(t *testing.T) {
	tests := map[string]struct {
		provideOptionsCtx bool
		cancelOptionsCtx  bool
		expectedRefreshes int
	}{
		"cancel Options.Ctx": {
			provideOptionsCtx: true,
			cancelOptionsCtx:  true,
			expectedRefreshes: 2,
		},
		"do not cancel Options.Ctx": {
			provideOptionsCtx: true,
			cancelOptionsCtx:  false,
			expectedRefreshes: 3,
		},
		"do not provide Options.Ctx": {
			provideOptionsCtx: false,
			cancelOptionsCtx:  false,
			expectedRefreshes: 3,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var (
				ctx    context.Context
				cancel = func() {}
			)
			if tc.provideOptionsCtx {
				ctx, cancel = context.WithCancel(context.Background())
				defer cancel()
			}

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
				Ctx:             ctx,
				RefreshInterval: 1 * time.Second,
			}
			jwks, err := keyfunc.Get(jwksURL, opts)
			if err != nil {
				t.Fatalf(logFmt, "Failed to get JWKS from testing URL.", err)
			}

			// Wait for the first refresh to occur to ensure the
			// JWKS gets refreshed at least once.
			time.Sleep(1100 * time.Millisecond)

			if tc.cancelOptionsCtx {
				cancel()
			}

			// Wait for another refresh cycle to occur to ensure the
			// JWKS either did or did not get refreshed depending on
			// whether the passed Options.Ctx has been canceled.
			time.Sleep(1101 * time.Millisecond)

			jwks.EndBackground()

			// Wait for another refresh cycle to occur to verify that
			// the JWKS did not get refreshed after EndBackground()
			// has been called.
			time.Sleep(1100 * time.Millisecond)

			count := atomic.LoadUint64(&counter)
			if count != uint64(tc.expectedRefreshes) {
				t.Fatalf("Expected %d refreshes, got %d.", tc.expectedRefreshes, count)
			}
		})
	}
}
