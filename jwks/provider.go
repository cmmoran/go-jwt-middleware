package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/sync/singleflight"

	"github.com/auth0/go-jwt-middleware/v2/internal/oidc"
)

// Provider handles fetching and managing JSON Web Key Sets (JWKS) from specified OIDC issuers.
// It provides functionality to retrieve JWKS either from the standard OIDC discovery endpoint
// or from a custom JWKS URI. The Provider supports multiple issuers and custom HTTP clients.
//
// The Provider offers two main implementations:
//   - Default Provider: Fetches JWKS directly without caching
//   - Caching Provider: Maintains a cache of JWKS to improve performance and reduce API calls
//
// For production use, it's recommended to use the Caching Provider configuration to avoid
// potential rate limiting and reduce latency. The Caching Provider can be configured with
// custom TTL values and refresh strategies.
//
// The Provider implements a KeyFunc that is compatible with JWT validators, making it
// suitable for JWT verification in authentication workflows.

type Provider struct {
	IssuerURL         *url.URL                   // Required.
	CustomJWKSURI     *url.URL                   // Optional.
	AdditionalIssuers []*IssuerWithCustomJWKSURI // Optional
	keyProvider       KeySetProvider
}

type IssuerWithCustomJWKSURI struct {
	IssuerURL     *url.URL
	CustomJWKSURI *url.URL
}

type KeySetProvider interface {
	ProvideKeySet(context.Context, url.URL, *url.URL) (*jose.JSONWebKeySet, error)
}

type defaultKeyProvider struct {
	client *http.Client
}

type cachingKeyProvider struct {
	*defaultKeyProvider
	*cachingProviderOptions
}

type cachedJWKS struct {
	jwks      *jose.JSONWebKeySet
	expiresAt time.Time
}

type cachingProviderOptions struct {
	cacheTTL           time.Duration
	mu                 sync.RWMutex
	cache              map[string]cachedJWKS
	sf                 singleflight.Group
	synchronousRefresh bool
}

// ProviderOption is how options for the Provider are set up.
type ProviderOption func(*Provider)

type CachingProviderOption func(*cachingProviderOptions)

// NewProvider builds and returns a new *Provider.
func NewProvider(issuerURL *url.URL, opts ...ProviderOption) *Provider {
	p := &Provider{
		IssuerURL: issuerURL,
		keyProvider: &defaultKeyProvider{
			client: &http.Client{},
		},
		AdditionalIssuers: make([]*IssuerWithCustomJWKSURI, 0),
	}

	for _, opt := range opts {
		opt(p)
	}

	if p.IssuerURL == nil {
		panic("NewProvider: issuerURL is required")
	}

	return p
}

func (x *defaultKeyProvider) ProvideKeySet(ctx context.Context, iss url.URL, jwksURI *url.URL) (*jose.JSONWebKeySet, error) {
	if jwksURI == nil {
		wkEndpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(ctx, x.client, iss)
		if err != nil {
			return nil, err
		}

		jwksURI, err = url.Parse(wkEndpoints.JWKSURI)
		if err != nil {
			return nil, fmt.Errorf("could not parse JWKS URI from well known endpoints: %w", err)
		}
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not build request to get JWKS: %w", err)
	}

	response, err := x.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = response.Body.Close()
	}()

	var jwks jose.JSONWebKeySet
	if err = json.NewDecoder(response.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("could not decode jwks: %w", err)
	}

	return &jwks, nil
}

func (x *cachingKeyProvider) ProvideKeySet(ctx context.Context, iss url.URL, custom *url.URL) (*jose.JSONWebKeySet, error) {
	issuer := iss.Hostname()

	// fast path
	x.mu.RLock()
	cached, ok := x.cache[issuer]
	x.mu.RUnlock()

	if ok && time.Now().Before(cached.expiresAt) {
		return cached.jwks, nil
	}

	if ok {
		// stale-while-refreshing
		_ = x.sf.DoChan(issuer, func() (any, error) {
			refreshCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			x.mu.Lock()
			defer x.mu.Unlock()
			return x.updateCacheLocked(refreshCtx, iss, custom)
		})
		return cached.jwks, nil
	}

	// no cache at all → single-flight fetch
	v := x.sf.DoChan(issuer, func() (any, error) {
		x.mu.Lock()
		defer x.mu.Unlock()
		return x.updateCacheLocked(ctx, iss, custom)
	})
	r := <-v
	if r.Err != nil {
		return nil, r.Err
	}
	return r.Val.(*jose.JSONWebKeySet), nil
}

func (x *cachingKeyProvider) updateCacheLocked(ctx context.Context, iss url.URL, custom *url.URL) (*jose.JSONWebKeySet, error) {
	issuer := iss.Hostname()
	jwks, err := x.defaultKeyProvider.ProvideKeySet(ctx, iss, custom)
	if err != nil {
		delete(x.cache, issuer) // ensure immediate removal on failure
		return nil, err
	}
	x.cache[issuer] = cachedJWKS{
		jwks:      jwks,
		expiresAt: time.Now().Add(x.cacheTTL),
	}
	return jwks, nil
}

// WithCustomJWKSURI will set a custom JWKS URI on the *Provider and
// call this directly inside the keyFunc in order to fetch the JWKS,
// skipping the oidc.GetWellKnownEndpointsFromIssuerURL call.
func WithCustomJWKSURI(jwksURI *url.URL) ProviderOption {
	return func(p *Provider) {
		p.CustomJWKSURI = jwksURI
	}
}

// WithCustomClient sets a custom *http.Client on the Provider.
func WithCustomClient(c *http.Client) ProviderOption {
	return func(p *Provider) {
		switch kp := p.keyProvider.(type) {
		case *defaultKeyProvider:
			kp.client = c
		case *cachingKeyProvider:
			kp.client = c
		}
	}
}

// WithAdditionalIssuers allows validation with mutliple IssuerURLs if desired. If multiple issuers are specified,
// a jwt may be signed by any of them and be considered valid
func WithAdditionalIssuers(issuerURL *url.URL, customJWKSURI *url.URL) ProviderOption {
	return func(p *Provider) {
		if issuerURL == nil {
			panic("WithAdditionalIssuers: issuerURL is required")
		}
		p.AdditionalIssuers = append(p.AdditionalIssuers, &IssuerWithCustomJWKSURI{
			IssuerURL:     issuerURL,
			CustomJWKSURI: customJWKSURI,
		})
	}
}

// WithCachingOptions enables caching and applies caching options.
func WithCachingOptions(opts ...CachingProviderOption) ProviderOption {
	return func(p *Provider) {
		var client *http.Client
		switch kp := p.keyProvider.(type) {
		case *defaultKeyProvider:
			client = kp.client
		case *cachingKeyProvider:
			client = kp.client
		default:
			client = &http.Client{}
		}

		o := &cachingProviderOptions{
			cacheTTL: time.Minute,
			cache:    make(map[string]cachedJWKS),
		}
		for _, opt := range opts {
			opt(o)
		}
		cp := &cachingKeyProvider{
			defaultKeyProvider: &defaultKeyProvider{
				client: client,
			},
			cachingProviderOptions: o,
		}
		p.keyProvider = cp
	}
}

// WithSynchronousRefresh sets whether the Provider blocks on refresh.
// If set to true, it will block and wait for the refresh to complete.
// If set to false (default), it will return the cached JWKS and trigger a background refresh.
func WithSynchronousRefresh(blocking bool) CachingProviderOption {
	return func(cp *cachingProviderOptions) {
		cp.synchronousRefresh = blocking
	}
}

func WithCacheTTL(ttl time.Duration) CachingProviderOption {
	return func(cp *cachingProviderOptions) {
		cp.cacheTTL = ttl
		if ttl == 0 {
			cp.cacheTTL = time.Minute
		}
	}
}

// KeyFunc adheres to the keyFunc signature that the Validator requires.
// While it returns an interface to adhere to keyFunc, as long as the
// error is nil the type will be *jose.JSONWebKeySet.
func (p *Provider) KeyFunc(ctx context.Context) (interface{}, error) {
	var (
		rawJwks *jose.JSONWebKeySet
		err     error
	)
	if rawJwks, err = p.keyProvider.ProvideKeySet(ctx, *p.IssuerURL, p.CustomJWKSURI); err != nil {
		return nil, err
	}

	if len(p.AdditionalIssuers) == 0 {
		return rawJwks, nil
	} else {
		for _, additionalIssuer := range p.AdditionalIssuers {
			if additionalJwks, nerr := p.keyProvider.ProvideKeySet(ctx, *additionalIssuer.IssuerURL, additionalIssuer.CustomJWKSURI); nerr != nil {
				err = errors.Join(err, nerr)
				continue
			} else {
				rawJwks.Keys = append(rawJwks.Keys, additionalJwks.Keys...)
			}
		}
		return rawJwks, err
	}
}
