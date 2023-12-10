package keyfunc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/MicahParks/jwkset"
)

// storage implements jwkset.Storage.
type storage struct {
	store jwkset.Storage
}

func newStorage(jwksURL string, options Options) (jwkset.Storage, error) {
	if options.Client == nil {
		options.Client = http.DefaultClient
	}
	if options.Ctx == nil {
		options.Ctx = context.Background()
	}
	if options.RefreshTimeout == 0 {
		options.RefreshTimeout = time.Minute
	}
	if options.RequestFactory == nil {
		options.RequestFactory = defaultRequestFactory
	}
	if options.ResponseExtractor == nil {
		options.ResponseExtractor = ResponseExtractorStatusOK
	}

	m := jwkset.NewMemoryStorage()
	addGivenKeys := func() error {
		for kid, key := range options.GivenKeys {
			metadata := jwkset.JWKMetadataOptions{
				ALG: jwkset.ALG(key.algorithm),
				KID: kid,
			}
			marshalOptions := jwkset.JWKMarshalOptions{
				Private: true,
			}
			jwkOpts := jwkset.JWKOptions{
				Marshal:  marshalOptions,
				Metadata: metadata,
			}
			jwk, err := jwkset.NewJWKFromKey(key.inter, jwkOpts)
			if err != nil {
				return fmt.Errorf("failed to create JWK from key: %w", err)
			}
			err = m.WriteKey(options.Ctx, jwk)
			if err != nil {
				return fmt.Errorf("failed to write JWK to given storage: %w", err)
			}
		}
		return nil
	}
	err := addGivenKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to add given keys to memory storage: %w", err)
	}

	u, err := url.ParseRequestURI(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse given URL %q: %w", jwksURL, err)
	}

	refresh := func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, options.RefreshTimeout)
		defer cancel()
		req, err := options.RequestFactory(ctx, u.String())
		if err != nil {
			return fmt.Errorf("failed to create HTTP request for JWK Set refresh: %w", err)
		}
		resp, err := options.Client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to perform HTTP request for JWK Set refresh: %w", err)
		}
		//goland:noinspection GoUnhandledErrorResult
		defer resp.Body.Close()
		raw, err := options.ResponseExtractor(ctx, resp)
		if err != nil {
			return fmt.Errorf("failed to extract response body: %w", err)
		}
		var jwks jwkset.JWKSMarshal
		err = json.Unmarshal(raw, &jwks)
		if err != nil {
			return fmt.Errorf("failed to decode JWK Set response: %w", err)
		}
		for _, marshal := range jwks.Keys {
			marshalOptions := jwkset.JWKMarshalOptions{
				Private: true,
			}
			jwk, err := jwkset.NewJWKFromMarshal(marshal, marshalOptions, jwkset.JWKValidateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create JWK from JWK Marshal: %w", err)
			}
			err = m.WriteKey(options.Ctx, jwk)
			if err != nil {
				return fmt.Errorf("failed to write JWK to memory storage: %w", err)
			}
		}
		if options.GivenKIDOverride {
			err = addGivenKeys()
			if err != nil {
				return fmt.Errorf("failed to add given keys to memory storage: %w", err)
			}
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(options.Ctx, options.RefreshTimeout)
	defer cancel()
	err = refresh(ctx)
	cancel()
	if err != nil && !options.TolerateInitialJWKHTTPError {
		return nil, fmt.Errorf("failed to perform first HTTP request for JWK Set: %w", err)
	}

	go func() { // Refresh goroutine.
		ticker := time.NewTicker(options.RefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-options.Ctx.Done():
				return
			case <-ticker.C:
				ctx, cancel = context.WithTimeout(options.Ctx, options.RefreshTimeout)
				err = refresh(ctx)
				cancel()
				if err != nil && options.RefreshErrorHandler != nil {
					options.RefreshErrorHandler(err)
				}
			}
		}
	}()

	return m, nil
}

func (s storage) DeleteKey(ctx context.Context, keyID string) (ok bool, err error) {
	return s.store.DeleteKey(ctx, keyID)
}
func (s storage) ReadKey(ctx context.Context, keyID string) (jwkset.JWK, error) {
	return s.store.ReadKey(ctx, keyID)
}
func (s storage) SnapshotKeys(ctx context.Context) ([]jwkset.JWK, error) {
	return s.store.SnapshotKeys(ctx)
}
func (s storage) WriteKey(ctx context.Context, jwk jwkset.JWK) error {
	return s.store.WriteKey(ctx, jwk)
}
