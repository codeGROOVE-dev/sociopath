// Package httpcache provides HTTP response caching with thundering herd prevention.
package httpcache

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codeGROOVE-dev/retry"
	"github.com/codeGROOVE-dev/sfcache"
	"github.com/codeGROOVE-dev/sfcache/pkg/store/localfs"
	"github.com/codeGROOVE-dev/sfcache/pkg/store/null"
	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
)

// UserAgent is the standard browser User-Agent string for all fetchers.
const UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0"

// Stats tracks cache hit/miss statistics.
type Stats struct {
	Hits   int64
	Misses int64
}

var globalStats atomic.Pointer[Stats]

func init() {
	globalStats.Store(&Stats{})
}

// CacheStats returns the current cache statistics.
func CacheStats() Stats {
	return *globalStats.Load()
}

// ResetStats resets the cache statistics.
func ResetStats() {
	globalStats.Store(&Stats{})
}

func recordHit() {
	for {
		old := globalStats.Load()
		updated := &Stats{Hits: old.Hits + 1, Misses: old.Misses}
		if globalStats.CompareAndSwap(old, updated) {
			return
		}
	}
}

func recordMiss() {
	for {
		old := globalStats.Load()
		updated := &Stats{Hits: old.Hits, Misses: old.Misses + 1}
		if globalStats.CompareAndSwap(old, updated) {
			return
		}
	}
}

// Cacher allows external cache implementations for sharing across packages.
type Cacher interface {
	GetSet(ctx context.Context, key string, fetch func(context.Context) ([]byte, error), ttl ...time.Duration) ([]byte, error)
	TTL() time.Duration
}

// Cache wraps sfcache for HTTP response caching.
type Cache struct {
	*sfcache.TieredCache[string, []byte]

	ttl time.Duration
}

// New creates a new Cache with disk persistence at ~/.cache/sociopath.
func New(ttl time.Duration) (*Cache, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	return NewWithPath(ttl, filepath.Join(cacheDir, "sociopath"))
}

// NewNull creates a Cache with no persistence (all gets miss, all sets discard).
func NewNull() *Cache {
	tc, err := sfcache.NewTiered[string, []byte](null.New[string, []byte]())
	if err != nil {
		panic("sfcache.NewTiered with null store: " + err.Error())
	}
	return &Cache{TieredCache: tc, ttl: 0}
}

// NewWithPath creates a new Cache with disk persistence at the specified path.
func NewWithPath(ttl time.Duration, cachePath string) (*Cache, error) {
	if err := os.MkdirAll(cachePath, 0o750); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}

	persist, err := localfs.New[string, []byte]("sociopath", cachePath)
	if err != nil {
		return nil, fmt.Errorf("create persistence layer: %w", err)
	}

	tc, err := sfcache.NewTiered[string, []byte](persist, sfcache.TTL(ttl))
	if err != nil {
		return nil, fmt.Errorf("create cache: %w", err)
	}

	return &Cache{TieredCache: tc, ttl: ttl}, nil
}

// TTL returns the default TTL for cache entries.
func (c *Cache) TTL() time.Duration {
	return c.ttl
}

// URLToKey converts a URL to a cache key using SHA256 hash.
func URLToKey(rawURL string) string {
	hash := sha256.Sum256([]byte(rawURL))
	return hex.EncodeToString(hash[:])
}

// HTTPError represents an HTTP error response.
type HTTPError struct {
	URL        string
	StatusCode int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d fetching %s", e.StatusCode, e.URL)
}

// ResponseValidator validates a response body. Returns true if cacheable.
type ResponseValidator func(body []byte) bool

// FetchURL fetches a URL with caching and thundering herd prevention.
// If cache is non-nil, uses GetSet to ensure only one request is made for concurrent calls.
func FetchURL(ctx context.Context, cache Cacher, client *http.Client, req *http.Request, logger *slog.Logger) ([]byte, error) {
	return FetchURLWithValidator(ctx, cache, client, req, logger, nil)
}

// FetchURLWithValidator fetches a URL with caching and optional response validation.
// If validator returns false, the response is returned but NOT cached.
func FetchURLWithValidator(
	ctx context.Context,
	cache Cacher,
	client *http.Client,
	req *http.Request,
	logger *slog.Logger,
	validator ResponseValidator,
) ([]byte, error) {
	// Build cache key - include auth marker if cookies present.
	cacheKey := req.URL.String()
	if client.Jar != nil && len(client.Jar.Cookies(req.URL)) > 0 {
		cacheKey += "|auth"
	}

	if cache == nil {
		if logger != nil {
			logger.Info("cache disabled", "url", req.URL.String())
		}
		recordMiss()
		return doFetch(ctx, client, req, logger)
	}

	var wasFetched bool
	data, err := cache.GetSet(ctx, URLToKey(cacheKey), func(ctx context.Context) ([]byte, error) {
		wasFetched = true
		recordMiss()
		if logger != nil {
			logger.Info("CACHE MISS", "url", req.URL.String())
		}
		body, fetchErr := doFetch(ctx, client, req, logger)
		if fetchErr != nil {
			// Cache HTTP errors to avoid hammering servers.
			var httpErr *HTTPError
			if errors.As(fetchErr, &httpErr) {
				return fmt.Appendf(nil, "ERROR:%d", httpErr.StatusCode), nil
			}
			// Cache network errors too (timeouts, DNS failures, connection refused).
			return fmt.Appendf(nil, "NETERR:%s", fetchErr.Error()), nil
		}
		// If validator fails, return error to prevent caching.
		if validator != nil && !validator(body) {
			if logger != nil {
				logger.Debug("skipping cache due to validation failure", "key", cacheKey)
			}
			return nil, &validationError{data: body}
		}
		return body, nil
	}, cache.TTL())

	if !wasFetched {
		recordHit()
		if logger != nil {
			logger.Debug("cache hit", "url", req.URL.String())
		}
	}

	// Handle validation failure - return the data but it wasn't cached.
	var validErr *validationError
	if errors.As(err, &validErr) {
		return validErr.data, nil
	}
	if err != nil {
		return nil, err
	}

	// Check if this is a cached error.
	s := string(data)
	if errCode, found := strings.CutPrefix(s, "ERROR:"); found {
		code, _ := strconv.Atoi(errCode) //nolint:errcheck // 0 is acceptable default
		return nil, &HTTPError{StatusCode: code, URL: req.URL.String()}
	}
	if errMsg, found := strings.CutPrefix(s, "NETERR:"); found {
		return nil, fmt.Errorf("cached network error: %s", errMsg)
	}

	return data, nil
}

type validationError struct{ data []byte }

func (*validationError) Error() string { return "validation failed" }

func doFetch(ctx context.Context, client *http.Client, req *http.Request, logger *slog.Logger) ([]byte, error) {
	// Limit total retry time to 2 seconds
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	return retry.DoWithData(
		func() ([]byte, error) {
			globalRateLimiter.Wait(req.URL.String(), logger)

			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close() //nolint:errcheck // intentional

			if resp.StatusCode != http.StatusOK {
				return nil, &HTTPError{StatusCode: resp.StatusCode, URL: req.URL.String()}
			}

			return io.ReadAll(resp.Body)
		},
		retry.Context(ctx),
		retry.Attempts(2),                     // single retry
		retry.Delay(200*time.Millisecond),     // delay before retry
		retry.MaxJitter(100*time.Millisecond), // small jitter
		retry.RetryIf(isRetryableError),       // only retry transient errors
		retry.OnRetry(func(n uint, err error) {
			if logger != nil {
				logger.Debug("retrying HTTP request", "attempt", n+1, "url", req.URL.String(), "error", err)
			}
		}),
	)
}

// isRetryableError returns true for transient errors that should be retried.
func isRetryableError(err error) bool {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		switch httpErr.StatusCode {
		case http.StatusTooManyRequests,
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout:
			return true
		default:
			return false // 4xx errors (except 429) are permanent
		}
	}
	// Network errors, timeouts, etc. are retryable
	return true
}

// Rate limiting.
var globalRateLimiter = newGlobalRateLimiter()

func newGlobalRateLimiter() *domainRateLimiter {
	return &domainRateLimiter{
		minDelay:  1100 * time.Millisecond,
		overrides: map[string]time.Duration{},
	}
}

type domainRateLimiter struct {
	overrides   map[string]time.Duration
	lastRequest sync.Map
	mu          sync.Map
	minDelay    time.Duration
}

func (r *domainRateLimiter) Wait(rawURL string, logger *slog.Logger) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return
	}
	domain := u.Host

	muI, _ := r.mu.LoadOrStore(domain, &sync.Mutex{})
	mu, ok := muI.(*sync.Mutex)
	if !ok {
		return
	}

	mu.Lock()
	defer mu.Unlock()

	delay := r.minDelay
	if override, ok := r.overrides[domain]; ok {
		delay = override
	}

	if lastI, ok := r.lastRequest.Load(domain); ok {
		if last, ok := lastI.(time.Time); ok {
			if elapsed := time.Since(last); elapsed < delay {
				waitTime := delay - elapsed
				if logger != nil {
					logger.Debug("rate limit pause", "domain", domain, "wait", waitTime)
				}
				time.Sleep(waitTime)
			}
		}
	}

	r.lastRequest.Store(domain, time.Now())
}

// ResolveRedirects follows HTTP, HTML meta refresh, and JavaScript redirects.
// Returns the final URL after following all redirects (up to maxRedirects).
// If no redirects are found, returns the original URL unchanged.
func ResolveRedirects(ctx context.Context, cache Cacher, rawURL string, logger *slog.Logger) string {
	doResolve := func() string {
		return resolveRedirectsImpl(ctx, rawURL, logger)
	}

	if cache == nil {
		return doResolve()
	}

	cacheKey := "redirect:" + URLToKey(rawURL)
	data, err := cache.GetSet(ctx, cacheKey, func(ctx context.Context) ([]byte, error) {
		return []byte(doResolve()), nil
	}, cache.TTL())
	if err != nil {
		return doResolve()
	}
	return string(data)
}

func resolveRedirectsImpl(ctx context.Context, rawURL string, logger *slog.Logger) string {
	const maxRedirects = 5

	// Create a client that doesn't follow redirects automatically
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects automatically
		},
	}

	currentURL := rawURL
	for range maxRedirects {
		globalRateLimiter.Wait(currentURL, logger)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, currentURL, http.NoBody)
		if err != nil {
			if logger != nil {
				logger.Debug("failed to create request for redirect resolution", "url", currentURL, "error", err)
			}
			break
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			if logger != nil {
				logger.Debug("failed to fetch URL for redirect resolution", "url", currentURL, "error", err)
			}
			break
		}

		// Check for HTTP redirect (3xx status codes)
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			resp.Body.Close() //nolint:errcheck,gosec // intentional
			if location == "" {
				break
			}
			// Resolve relative redirect URLs
			nextURL := resolveRelativeURL(currentURL, location)
			if logger != nil {
				logger.Debug("following HTTP redirect", "from", currentURL, "to", nextURL, "status", resp.StatusCode)
			}
			currentURL = nextURL
			continue
		}

		// For 200 OK responses, check for HTML/JS redirects
		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // Read up to 64KB
			resp.Body.Close()                                           //nolint:errcheck,gosec // intentional
			if err != nil {
				break
			}

			redirectURL := htmlutil.ExtractRedirectURL(string(body))
			if redirectURL == "" {
				break // No redirect found, we're done
			}

			// Resolve relative redirect URLs
			nextURL := resolveRelativeURL(currentURL, redirectURL)
			if logger != nil {
				logger.Debug("following HTML/JS redirect", "from", currentURL, "to", nextURL)
			}
			currentURL = nextURL
			continue
		}

		resp.Body.Close() //nolint:errcheck,gosec // intentional
		break             // Non-redirect, non-OK status
	}

	return currentURL
}

// resolveRelativeURL resolves a potentially relative URL against a base URL.
func resolveRelativeURL(baseURL, ref string) string {
	// Already absolute
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return ref
	}

	// Handle protocol-relative URLs
	if strings.HasPrefix(ref, "//") {
		return base.Scheme + ":" + ref
	}

	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}

	return base.ResolveReference(refURL).String()
}
