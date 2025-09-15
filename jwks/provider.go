package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/sync/semaphore"

	"github.com/auth0/go-jwt-middleware/v2/internal/oidc"
)

// Provider handles getting JWKS from the specified IssuerURL and exposes
// KeyFunc which adheres to the keyFunc signature that the Validator requires.
// Most likely you will want to use the CachingProvider as it handles
// getting and caching JWKS which can help reduce request time and potential
// rate limiting from your provider.
type Provider struct {
	IssuerURL           *url.URL   // Required.
	CustomJWKSURI       *url.URL   // Optional.
	AdditionalProviders []Provider // Optional
	Client              *http.Client
}

// ProviderOption is how options for the Provider are set up.
type ProviderOption func(*Provider)

// NewProvider builds and returns a new *Provider.
func NewProvider(issuerURL *url.URL, opts ...ProviderOption) *Provider {
	p := &Provider{
		Client:              &http.Client{},
		AdditionalProviders: make([]Provider, 0),
	}

	if issuerURL != nil {
		p.IssuerURL = issuerURL
	}

	for _, opt := range opts {
		opt(p)
	}

	for _, provider := range p.AdditionalProviders {
		if provider.Client == nil {
			provider.Client = p.Client
		}
	}

	return p
}

// WithCustomJWKSURI will set a custom JWKS URI on the *Provider and
// call this directly inside the keyFunc in order to fetch the JWKS,
// skipping the oidc.GetWellKnownEndpointsFromIssuerURL call.
func WithCustomJWKSURI(jwksURI *url.URL) ProviderOption {
	return func(p *Provider) {
		p.CustomJWKSURI = jwksURI
	}
}

// WithCustomClient will set a custom *http.Client on the *Provider
func WithCustomClient(c *http.Client) ProviderOption {
	return func(p *Provider) {
		p.Client = c
		for _, provider := range p.AdditionalProviders {
			provider.Client = c
		}
	}
}

// WithAdditionalProviders allows validation with mutliple IssuerURLs if desired. If multiple issuers are specified,
// a jwt may be signed by any of them and be considered valid
func WithAdditionalProviders(issuerURL *url.URL, customJWKSURI *url.URL) ProviderOption {
	return func(p *Provider) {
		p.AdditionalProviders = append(p.AdditionalProviders, Provider{
			IssuerURL:     issuerURL,
			CustomJWKSURI: customJWKSURI,
			Client:        p.Client,
		})
	}
}

// KeyFunc adheres to the keyFunc signature that the Validator requires.
// While it returns an interface to adhere to keyFunc, as long as the
// error is nil the type will be *jose.JSONWebKeySet.
func (p *Provider) KeyFunc(ctx context.Context) (any, error) {
	var jwks *jose.JSONWebKeySet
	rawJwks, err := p.keyFunc(ctx)
	if err != nil {
		return nil, err
	}
	if jwks = rawJwks.(*jose.JSONWebKeySet); jwks == nil {
		return nil, errors.New("keyFunc returned a non *jose.JSONWebKeySet")
	}

	if len(p.AdditionalProviders) == 0 {
		return jwks, nil
	} else {
		var errs error
		for _, provider := range p.AdditionalProviders {
			if rawJwks, err = provider.keyFunc(ctx); err != nil {
				errs = errors.Join(errs, err)
				continue
			} else {
				jwks.Keys = append(jwks.Keys, rawJwks.(*jose.JSONWebKeySet).Keys...)
			}
		}
		return jwks, errs
	}
}

func (p *Provider) keyFunc(ctx context.Context) (any, error) {
	jwksURI := p.CustomJWKSURI
	if jwksURI == nil {
		wkEndpoints, err := oidc.GetWellKnownEndpointsFromIssuerURL(ctx, p.Client, *p.IssuerURL)
		if err != nil {
			return nil, err
		}

		jwksURI, err = url.Parse(wkEndpoints.JWKSURI)
		if err != nil {
			return nil, fmt.Errorf("could not parse JWKS URI from well known endpoints: %w", err)
		}
	}

	return p.doResolve(ctx, jwksURI)
}

func (p *Provider) doResolve(ctx context.Context, jwksURI *url.URL) (any, error) {
	var (
		reader io.ReadCloser
		req    *http.Request
		res    *http.Response
		err    error
		errs   error
	)

	switch jwksURI.Scheme {
	case "", "file":
		reader, err = os.Open(jwksURI.Path)
		if err != nil {
			errs = errors.Join(err, fmt.Errorf(`unable to fetch JSON Web Keys from location "%s"`, jwksURI.String()))
			return nil, errs
		}
		defer func(reader io.ReadCloser) {
			_ = reader.Close()
		}(reader)

	case "http", "https":
		if req, err = http.NewRequestWithContext(ctx, "GET", jwksURI.String(), nil); err != nil {
			errs = errors.Join(err, fmt.Errorf(`unable to fetch JSON Web Keys from location "%s"`, jwksURI.String()))
			return nil, errs
		}
		if res, err = p.Client.Do(req); err != nil {
			errs = errors.Join(err, fmt.Errorf(`unable to fetch JSON Web Keys from location "%s"`, jwksURI.String()))
			return nil, errs
		}
		reader = res.Body
		defer func(reader io.ReadCloser) {
			_ = reader.Close()
		}(reader)

		if res.StatusCode < 200 || res.StatusCode >= 400 {
			errs = errors.Join(err, fmt.Errorf(`expected successful status code from location "%s", but received code "%d"`, jwksURI.String(), res.StatusCode))
			return nil, errs
		}

	default:
		errs = errors.Join(err, fmt.Errorf(`unable to fetch JSON Web Keys from location "%s" because URL scheme "%s" is not supported`, jwksURI.String(), jwksURI.Scheme))
		return nil, errs
	}

	jwks := new(jose.JSONWebKeySet)
	if err = json.NewDecoder(reader).Decode(jwks); err != nil {
		errs = errors.Join(err, fmt.Errorf("could not decode jwks: %w", err))
		return nil, errs
	}
	slices.SortFunc(jwks.Keys, func(a, b jose.JSONWebKey) int {
		return strings.Compare(a.KeyID, b.KeyID)
	})

	return jwks, nil
}

// CachingProvider handles getting JWKS from the specified IssuerURL
// and caching them for CacheTTL time. It exposes KeyFunc which adheres
// to the keyFunc signature that the Validator requires.
// When the CacheTTL value has been reached, a JWKS refresh will be triggered
// in the background and the existing cached JWKS will be returned until the
// JWKS cache is updated, or if the request errors then it will be evicted from
// the cache.
// The cache is keyed by the issuer's hostname. The synchronousRefresh
// field determines whether the refresh is done synchronously or asynchronously.
// This can be set using the WithSynchronousRefresh option.
type CachingProvider struct {
	*Provider
	CacheTTL           time.Duration
	mu                 sync.RWMutex
	cache              map[string]cachedJWKS
	sem                *semaphore.Weighted
	synchronousRefresh bool
}

type cachedJWKS struct {
	jwks      *jose.JSONWebKeySet
	expiresAt time.Time
}

type CachingProviderOption func(*CachingProvider)

// NewCachingProvider builds and returns a new CachingProvider.
// If cacheTTL is zero then a default value of 1 minute will be used.
func NewCachingProvider(issuerURL *url.URL, cacheTTL time.Duration, opts ...any) *CachingProvider {
	if cacheTTL == 0 {
		cacheTTL = 1 * time.Minute
	}

	var providerOpts []ProviderOption
	var cachingOpts []CachingProviderOption

	for _, opt := range opts {
		switch o := opt.(type) {
		case ProviderOption:
			providerOpts = append(providerOpts, o)
		case CachingProviderOption:
			cachingOpts = append(cachingOpts, o)
		default:
			panic(fmt.Sprintf("invalid option type: %T", o))
		}
	}
	cp := &CachingProvider{
		Provider:           NewProvider(issuerURL, providerOpts...),
		CacheTTL:           cacheTTL,
		cache:              map[string]cachedJWKS{},
		sem:                semaphore.NewWeighted(1),
		synchronousRefresh: false,
	}

	for _, opt := range cachingOpts {
		opt(cp)
	}

	return cp
}

// KeyFunc adheres to the keyFunc signature that the Validator requires.
// While it returns an interface to adhere to keyFunc, as long as the
// error is nil the type will be *jose.JSONWebKeySet.
func (c *CachingProvider) KeyFunc(ctx context.Context) (any, error) {
	c.mu.RLock()

	issuer := c.IssuerURL.Hostname()

	if cached, ok := c.cache[issuer]; ok {
		if time.Now().After(cached.expiresAt) && c.sem.TryAcquire(1) {
			if !c.synchronousRefresh {
				go func() {
					defer c.sem.Release(1)
					refreshCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					_, err := c.refreshKey(refreshCtx, issuer)

					if err != nil {
						c.mu.Lock()
						delete(c.cache, issuer)
						c.mu.Unlock()
					}
				}()
				c.mu.RUnlock()
				return cached.jwks, nil
			} else {
				c.mu.RUnlock()
				defer c.sem.Release(1)
				return c.refreshKey(ctx, issuer)
			}
		}
		c.mu.RUnlock()
		return cached.jwks, nil
	}

	c.mu.RUnlock()
	return c.refreshKey(ctx, issuer)
}

// WithSynchronousRefresh sets whether the CachingProvider blocks on refresh.
// If set to true, it will block and wait for the refresh to complete.
// If set to false (default), it will return the cached JWKS and trigger a background refresh.
func WithSynchronousRefresh(blocking bool) CachingProviderOption {
	return func(cp *CachingProvider) {
		cp.synchronousRefresh = blocking
	}
}

func (c *CachingProvider) refreshKey(ctx context.Context, issuer string) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	jwks, err := c.Provider.KeyFunc(ctx)
	if err != nil {
		return nil, err
	}

	c.cache[issuer] = cachedJWKS{
		jwks:      jwks.(*jose.JSONWebKeySet),
		expiresAt: time.Now().Add(c.CacheTTL),
	}

	return jwks, nil
}
