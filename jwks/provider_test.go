package jwks

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/auth0/go-jwt-middleware/v2/internal/oidc"
)

func Test_JWKSProvider(t *testing.T) {
	requestCount := new(atomic.Int32)
	requestCount.Store(0)

	expectedJWKS, err := generateJWKS()
	require.NoError(t, err)

	expectedCustomJWKS, err := generateJWKS()
	require.NoError(t, err)

	testServer := setupTestServer(t, expectedJWKS, expectedCustomJWKS, requestCount)
	defer testServer.Close()

	testServerURL, err := url.Parse(testServer.URL)
	require.NoError(t, err)

	t.Run("It correctly fetches the JWKS after calling the discovery endpoint", func(t *testing.T) {
		provider := NewProvider(testServerURL)
		actualJWKS, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)

		if !cmp.Equal(expectedJWKS, actualJWKS) {
			t.Fatalf("jwks did not match: %s", cmp.Diff(expectedJWKS, actualJWKS))
		}
	})

	t.Run("It skips the discovery if a custom JWKS_URI is provided", func(t *testing.T) {
		customJWKSURI, err := url.Parse(testServer.URL + "/custom/jwks.json")
		require.NoError(t, err)

		provider := NewProvider(testServerURL, WithCustomJWKSURI(customJWKSURI))
		actualJWKS, err := provider.KeyFunc(context.Background())
		require.NoError(t, err)

		if !cmp.Equal(expectedCustomJWKS, actualJWKS) {
			t.Fatalf("jwks did not match: %s", cmp.Diff(expectedCustomJWKS, actualJWKS))
		}
	})

	t.Run("It uses the specified custom client", func(t *testing.T) {
		client := &http.Client{
			Timeout: time.Hour, // Unused value. We only need this to have a client different from the default.
		}
		provider := NewProvider(testServerURL, WithCustomClient(client))
		if !cmp.Equal(client, provider.keyProvider.(*defaultKeyProvider).client) {
			t.Fatalf("expected custom client %#v to be configured. Got: %#v", client, provider.keyProvider.(*defaultKeyProvider).client)
		}
	})

	t.Run("It tells the provider to cancel fetching the JWKS if request is cancelled", func(t *testing.T) {
		ctx := context.Background()
		ctx, cancel := context.WithTimeout(ctx, 0)
		defer cancel()

		provider := NewProvider(testServerURL)
		_, err := provider.KeyFunc(ctx)
		if !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Fatalf("was expecting context deadline to exceed but error is: %v", err)
		}
	})

	t.Run("It eventually re-caches the JWKS if they have expired when using CachingProvider", func(t *testing.T) {
		requestCount.Store(0)
		expiredCachedJWKS, eerr := generateJWKS()
		require.NoError(t, eerr)

		provider := NewProvider(testServerURL, WithCachingOptions(WithCacheTTL(5*time.Minute)))
		provider.keyProvider.(*cachingKeyProvider).cachingProviderOptions.cache[testServerURL.Hostname()] = cachedJWKS{
			jwks:      expiredCachedJWKS,
			expiresAt: time.Now().Add(-10 * time.Minute),
		}
		if !cmp.Equal(expiredCachedJWKS, provider.keyProvider.(*cachingKeyProvider).cachingProviderOptions.cache[testServerURL.Hostname()].jwks) {
			t.Fatalf("jwks did not match: %s", cmp.Diff(expiredCachedJWKS, provider.keyProvider.(*cachingKeyProvider).cachingProviderOptions.cache[testServerURL.Hostname()].jwks))
		}

		returnedJWKS, rerr := provider.KeyFunc(context.Background())
		require.NoError(t, rerr)

		if !cmp.Equal(expiredCachedJWKS, returnedJWKS) {
			t.Fatalf("jwks did not match: %s", cmp.Diff(expiredCachedJWKS, returnedJWKS))
		}

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			returnedJWKS, err = provider.KeyFunc(context.Background())
			require.NoError(c, err)

			require.True(c, cmp.Equal(expectedJWKS, returnedJWKS))
			require.Equal(c, int32(2), requestCount.Load())
		}, 1*time.Second, 50*time.Millisecond, "JWKS did not update")

		cacheExpiresAt := provider.keyProvider.(*cachingKeyProvider).cachingProviderOptions.cache[testServerURL.Hostname()].expiresAt
		if !time.Now().Before(cacheExpiresAt) {
			t.Fatalf("wanted cache item expiration to be in the future but it was not: %s", cacheExpiresAt)
		}
	})

	t.Run(
		"It only calls the API once when multiple requests come in when using the CachingProvider",
		func(t *testing.T) {
			requestCount.Store(0)

			provider := NewProvider(testServerURL, WithCachingOptions(WithCacheTTL(5*time.Minute)))

			var wg sync.WaitGroup
			for i := 0; i < 50; i++ {
				wg.Add(1)
				go func() {
					_, _ = provider.KeyFunc(context.Background())
					wg.Done()
				}()
			}
			wg.Wait()

			assert.Equalf(t, int32(2), requestCount.Load(), "only wanted 2 requests (well known and jwks) , but we got %d requests", requestCount.Load())
		},
	)

	t.Run("It sets the caching TTL to 1 if 0 is provided when using the CachingProvider", func(t *testing.T) {
		provider := NewProvider(testServerURL, WithCachingOptions(WithCacheTTL(0)))
		if provider.keyProvider.(*cachingKeyProvider).cachingProviderOptions.cacheTTL != time.Minute {
			t.Fatalf("was expecting cache ttl to be 1 minute")
		}
	})

	t.Run(
		"It fails to parse the jwks uri after fetching it from the discovery endpoint if malformed",
		func(t *testing.T) {
			malformedURL, merr := url.Parse(testServer.URL + "/malformed")
			require.NoError(t, merr)

			provider := NewProvider(malformedURL)
			_, err = provider.KeyFunc(context.Background())
			if !strings.Contains(err.Error(), "could not parse JWKS URI from well known endpoints") {
				t.Fatalf("wanted an error, but got %s", err)
			}
		},
	)

	t.Run("It only calls the API once when multiple requests come in when using the CachingProvider with expired cache", func(t *testing.T) {
		initialJWKS, err := generateJWKS()
		require.NoError(t, err)
		requestCount.Store(0)

		provider := NewProvider(testServerURL, WithCachingOptions(WithCacheTTL(5*time.Minute)))
		provider.keyProvider.(*cachingKeyProvider).cachingProviderOptions.cache[testServerURL.Hostname()] = cachedJWKS{
			jwks:      initialJWKS,
			expiresAt: time.Now(),
		}

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				_, _ = provider.KeyFunc(context.Background())
				wg.Done()
			}()
		}
		wg.Wait()

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			returnedJWKS, rerr := provider.KeyFunc(context.Background())
			require.NoError(c, rerr)

			require.True(c, cmp.Equal(expectedJWKS, returnedJWKS))
			require.Equal(c, int32(2), requestCount.Load())
		}, 1*time.Second, 50*time.Millisecond, "JWKS did not update")
	})

	t.Run("It only calls the API once when multiple requests come in when using the CachingProvider with no cache", func(t *testing.T) {
		provider := NewProvider(testServerURL, WithCachingOptions(WithCacheTTL(5*time.Minute)))
		requestCount.Store(0)

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				_, _ = provider.KeyFunc(context.Background())
				wg.Done()
			}()
		}
		wg.Wait()

		if requestCount.Load() != int32(2) {
			t.Fatalf("only wanted 2 requests (well known and jwks) , but we got %d requests", requestCount.Load())
		}
	})

	t.Run("Should delete cache entry if the refresh request fails", func(t *testing.T) {
		malformedURL, merr := url.Parse(testServer.URL + "/malformed")
		require.NoError(t, merr)

		expiredCachedJWKS, eerr := generateJWKS()
		require.NoError(t, eerr)

		provider := NewProvider(malformedURL, WithCachingOptions(WithCacheTTL(5*time.Minute)))
		provider.keyProvider.(*cachingKeyProvider).cachingProviderOptions.cache[malformedURL.Hostname()] = cachedJWKS{
			jwks:      expiredCachedJWKS,
			expiresAt: time.Now().Add(-10 * time.Minute),
		}

		// Trigger the refresh of the JWKS, which should return the cached JWKS
		returnedJWKS, rerr := provider.KeyFunc(context.Background())
		require.NoError(t, rerr)
		assert.Equal(t, expiredCachedJWKS, returnedJWKS)

		// Eventually it should return a nil JWKS
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			returnedJWKS, err = provider.KeyFunc(context.Background())
			require.Error(c, err)

			require.Nil(c, returnedJWKS)

			currentCachedJWKS := provider.keyProvider.(*cachingKeyProvider).cachingProviderOptions.cache[malformedURL.Hostname()].jwks

			require.Nil(c, currentCachedJWKS)
		}, 1*time.Second, 50*time.Millisecond, "JWKS did not get uncached")
	})
	t.Run("It only calls the API once when multiple requests come in when using the CachingProvider with expired cache (WithSynchronousRefresh)", func(t *testing.T) {
		initialJWKS, ierr := generateJWKS()
		require.NoError(t, ierr)
		requestCount.Store(0)

		provider := NewProvider(testServerURL, WithCachingOptions(WithCacheTTL(5*time.Minute), WithSynchronousRefresh(true)))
		provider.keyProvider.(*cachingKeyProvider).cachingProviderOptions.cache[testServerURL.Hostname()] = cachedJWKS{
			jwks:      initialJWKS,
			expiresAt: time.Now(),
		}

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				_, _ = provider.KeyFunc(context.Background())
				wg.Done()
			}()
		}
		wg.Wait()
		// No need for Eventually since we're not blocking on refresh.
		returnedJWKS, rerr := provider.KeyFunc(context.Background())
		require.NoError(t, rerr)
		assert.True(t, cmp.Equal(expectedJWKS, returnedJWKS))

		// Non-blocking behavior may allow extra API calls before the cache updates.
		assert.Equal(t, int32(2), requestCount.Load(), "only wanted 2 requests (well known and jwks), but we got %d requests", requestCount.Load())
	})

	t.Run("It only calls the API once when multiple requests come in when using the CachingProvider with no cache (WithSynchronousRefresh)", func(t *testing.T) {
		provider := NewProvider(testServerURL, WithCachingOptions(WithCacheTTL(5*time.Minute), WithSynchronousRefresh(true)))
		requestCount.Store(0)

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				_, _ = provider.KeyFunc(context.Background())
				wg.Done()
			}()
		}
		wg.Wait()

		assert.EqualValues(t, int32(2), requestCount.Load(), "only wanted 2 requests (well known and jwks), but we got %d requests", requestCount.Load())
	})
	t.Run("It correctly applies both ProviderOptions and cachingProviderOptions when using the CachingProvider without breaking", func(t *testing.T) {
		issuerURL, _ := url.Parse("https://example.com")
		jwksURL, _ := url.Parse("https://example.com/jwks")
		customClient := &http.Client{Timeout: 10 * time.Second}

		provider := NewProvider(
			issuerURL,
			WithCachingOptions(WithSynchronousRefresh(true), WithCacheTTL(30*time.Second)),
			WithCustomJWKSURI(jwksURL),
			WithCustomClient(customClient),
		)

		assert.Equal(t, jwksURL, provider.CustomJWKSURI, "CustomJWKSURI should be set correctly")
		assert.Equal(t, customClient, provider.keyProvider.(*cachingKeyProvider).client, "Custom HTTP client should be set correctly")
		assert.True(t, provider.keyProvider.(*cachingKeyProvider).cachingProviderOptions.synchronousRefresh, "Synchronous refresh should be enabled")
	})
}

func generateJWKS() (*jose.JSONWebKeySet, error) {
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key")
	}

	rawCertificate, err := x509.CreateCertificate(
		rand.Reader,
		certificate,
		certificate,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate")
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:   privateKey,
				KeyID: "kid",
				Certificates: []*x509.Certificate{
					{
						Raw: rawCertificate,
					},
				},
				CertificateThumbprintSHA1:   []uint8{},
				CertificateThumbprintSHA256: []uint8{},
			},
		},
	}

	return &jwks, nil
}

func setupTestServer(
	t *testing.T,
	expectedJWKS *jose.JSONWebKeySet,
	expectedCustomJWKS *jose.JSONWebKeySet,
	requestCount *atomic.Int32,
) (server *httptest.Server) {
	t.Helper()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		switch r.URL.String() {
		case "/malformed/.well-known/openid-configuration":
			wk := oidc.WellKnownEndpoints{JWKSURI: ":"}
			err := json.NewEncoder(w).Encode(wk)
			require.NoError(t, err)
		case "/.well-known/openid-configuration":
			wk := oidc.WellKnownEndpoints{JWKSURI: server.URL + "/.well-known/jwks.json"}
			err := json.NewEncoder(w).Encode(wk)
			require.NoError(t, err)
		case "/.well-known/jwks.json":
			err := json.NewEncoder(w).Encode(expectedJWKS)
			require.NoError(t, err)
		case "/custom/jwks.json":
			err := json.NewEncoder(w).Encode(expectedCustomJWKS)
			require.NoError(t, err)
		default:
			t.Fatalf("was not expecting to handle the following url: %s", r.URL.String())
		}
	})

	return httptest.NewServer(handler)
}
