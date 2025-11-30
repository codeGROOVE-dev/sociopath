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

// FetchURL fetches a URL with caching support.
// If cache is non-nil and contains the URL, returns cached data.
// Otherwise, executes the HTTP request, caches successful responses (HTTP 200), and returns the body.
// Returns an error if the HTTP status is not 200 OK.
// The caller must set all necessary headers on the request before calling this function.
func FetchURL(ctx context.Context, cache HTTPCache, client *http.Client, req *http.Request, logger *slog.Logger) ([]byte, error) {
	url := req.URL.String()

	// Check cache
	if cache != nil {
		if data, _, _, found := cache.Get(ctx, url); found {
			if logger != nil {
				logger.Debug("cache hit", "url", url)
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
		return nil, &HTTPError{StatusCode: resp.StatusCode, URL: url}
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Cache successful response (async, errors intentionally ignored)
	if cache != nil {
		_ = cache.SetAsync(ctx, url, body, "", nil) //nolint:errcheck // async, error ignored
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
