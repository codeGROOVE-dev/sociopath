// Package cache provides HTTP caching interfaces and utilities.
package cache

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// HTTPCache defines the interface for caching HTTP responses.
type HTTPCache interface {
	Get(ctx context.Context, url string) (data []byte, etag string, headers map[string]string, found bool)
	SetAsync(ctx context.Context, url string, data []byte, etag string, headers map[string]string) error
	SetAsyncWithTTL(ctx context.Context, url string, data []byte, etag string, headers map[string]string, ttl time.Duration) error
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
func FetchURLWithValidator(ctx context.Context, cache HTTPCache, client *http.Client, req *http.Request, logger *slog.Logger, validator ResponseValidator) ([]byte, error) {
	// Build cache key that includes auth state to avoid mixing authenticated/unauthenticated responses
	cacheKey := req.URL.String()
	if client.Jar != nil {
		cookies := client.Jar.Cookies(req.URL)
		if len(cookies) > 0 {
			cacheKey += "|auth"
		}
	}

	// Check cache
	if cache != nil {
		if data, _, _, found := cache.Get(ctx, cacheKey); found {
			if logger != nil {
				logger.Debug("cache hit", "key", cacheKey)
				logger.Debug("response body", "url", req.URL.String(), "body", string(data))
			}
			return data, nil
		}
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // error ignored intentionally

	// Check status code
	if resp.StatusCode != http.StatusOK {
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
	}
	if cache != nil && !shouldCache && logger != nil {
		logger.Debug("skipping cache due to validation failure", "key", cacheKey)
	}

	if logger != nil {
		logger.Debug("response body", "url", req.URL.String(), "body", string(body))
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
