// Package cache provides HTTP caching interfaces and utilities.
package cache

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const errorTTL = 5 * 24 * time.Hour // Cache HTTP errors for 5 days

// globalRateLimiter enforces minimum delay between requests to the same domain.
// This prevents overwhelming servers even when running concurrent goroutines.
var globalRateLimiter = NewDomainRateLimiter(600 * time.Millisecond)

// Stats holds cache hit/miss statistics.
type Stats struct {
	Hits   int64
	Misses int64
}

// HitRate returns the cache hit rate as a percentage (0-100).
func (s Stats) HitRate() float64 {
	total := s.Hits + s.Misses
	if total == 0 {
		return 0
	}
	return float64(s.Hits) / float64(total) * 100
}

// HTTPCache defines the interface for caching HTTP responses.
type HTTPCache interface {
	Get(ctx context.Context, url string) (data []byte, etag string, headers map[string]string, found bool)
	SetAsync(ctx context.Context, url string, data []byte, etag string, headers map[string]string) error
	SetAsyncWithTTL(ctx context.Context, url string, data []byte, etag string, headers map[string]string, ttl time.Duration) error
	RecordHit()
	RecordMiss()
	Stats() Stats
}

// ResponseValidator is a function that validates a response body.
// Returns true if the response should be cached, false otherwise.
type ResponseValidator func(body []byte) bool

// FetchURL fetches a URL with caching support.
// If cache is non-nil and contains the URL, returns cached data.
// Otherwise, executes the HTTP request, caches successful responses (HTTP 200), and returns the body.
// Returns an error if the HTTP status is not 200 OK.
// The caller must set all necessary headers on the request before calling this function.
func FetchURL(ctx context.Context, cache HTTPCache, client *http.Client, req *http.Request, logger *slog.Logger) ([]byte, error) {
	return FetchURLWithValidator(ctx, cache, client, req, logger, nil)
}

// FetchURLWithValidator fetches a URL with caching support and optional response validation.
// If validator is provided and returns false, the response is NOT cached but still returned.
// This is useful for avoiding caching of incomplete/shell responses.
func FetchURLWithValidator(
	ctx context.Context,
	cache HTTPCache,
	client *http.Client,
	req *http.Request,
	logger *slog.Logger,
	validator ResponseValidator,
) ([]byte, error) {
	// Build cache key that includes auth state to avoid mixing authenticated/unauthenticated responses
	cacheKey := req.URL.String()
	if client.Jar != nil {
		cookies := client.Jar.Cookies(req.URL)
		if len(cookies) > 0 {
			cacheKey += "|auth"
		}
	}

	// Check cache
	if cache == nil {
		if logger != nil {
			logger.Info("cache disabled", "url", req.URL.String())
		}
	} else {
		if data, _, _, found := cache.Get(ctx, cacheKey); found {
			cache.RecordHit()
			// Check if this is a cached error (format: "ERROR:status_code")
			if s := string(data); strings.HasPrefix(s, "ERROR:") {
				code, _ := strconv.Atoi(strings.TrimPrefix(s, "ERROR:")) //nolint:errcheck // parse error defaults to 0 which is acceptable
				if logger != nil {
					logger.Debug("cache hit (error)", "key", cacheKey, "status", code)
				}
				return nil, &HTTPError{StatusCode: code, URL: req.URL.String()}
			}
			if logger != nil {
				logger.Debug("cache hit", "key", cacheKey)
			}
			return data, nil
		}
		cache.RecordMiss()
		if logger != nil {
			logger.Info("cache miss", "url", req.URL.String(), "key", cacheKey)
		}
	}

	// Rate limit: wait if we've recently hit this domain
	globalRateLimiter.Wait(req.URL.String())

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // error ignored intentionally

	// Check status code - cache errors for 5 days to avoid hammering servers
	if resp.StatusCode != http.StatusOK {
		if cache != nil {
			errData := []byte(fmt.Sprintf("ERROR:%d", resp.StatusCode))
			_ = cache.SetAsyncWithTTL(ctx, cacheKey, errData, "", nil, errorTTL) //nolint:errcheck // async write errors are non-fatal
			if logger != nil {
				logger.Info("cache store",
					"url", req.URL.String(), "key", cacheKey,
					"status", resp.StatusCode, "bytes", len(errData), "ttl", errorTTL)
			}
		}
		return nil, &HTTPError{StatusCode: resp.StatusCode, URL: req.URL.String()}
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Cache successful response only if validator passes (or no validator)
	shouldCache := validator == nil || validator(body)
	if cache != nil && shouldCache {
		_ = cache.SetAsync(ctx, cacheKey, body, "", nil) //nolint:errcheck // async, error ignored
		if logger != nil {
			logger.Info("cache store", "url", req.URL.String(), "key", cacheKey, "status", 200, "bytes", len(body), "ttl", "default")
		}
	}
	if cache != nil && !shouldCache && logger != nil {
		logger.Debug("skipping cache due to validation failure", "key", cacheKey)
	}

	return body, nil
}

// HTTPError represents an HTTP error response.
type HTTPError struct {
	URL        string
	StatusCode int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d fetching %s", e.StatusCode, e.URL)
}
