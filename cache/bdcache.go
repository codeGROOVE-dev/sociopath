package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/codeGROOVE-dev/bdcache"
	"github.com/codeGROOVE-dev/bdcache/persist/localfs"
)

// BDCache wraps bdcache to implement the HTTPCache interface.
type BDCache struct {
	cache *bdcache.Cache[string, *CachedResponse]
	ttl   time.Duration
}

// CachedResponse holds HTTP response data.
//
//nolint:govet // fieldalignment: intentional layout for clarity
type CachedResponse struct {
	Data    []byte
	Headers map[string]string
	ETag    string
}

// New creates a new BDCache with disk persistence.
// The cache directory defaults to ~/.cache/sociopath.
// ttl is the default time-to-live for cached entries.
// Use NewWithPath to specify a custom cache directory.
func New(ttl time.Duration) (*BDCache, error) {
	// Determine cache directory
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		// Fallback to temp dir if user cache dir not available
		cacheDir = os.TempDir()
	}
	cachePath := filepath.Join(cacheDir, "sociopath")
	return NewWithPath(ttl, cachePath)
}

// NewWithPath creates a new BDCache with disk persistence at the specified path.
func NewWithPath(ttl time.Duration, cachePath string) (*BDCache, error) {
	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cachePath, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Create persistence layer
	persist, err := localfs.New[string, *CachedResponse]("sociopath", cachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create persistence layer: %w", err)
	}

	// Create bdcache with disk persistence
	ctx := context.Background()
	cache, err := bdcache.New[string, *CachedResponse](
		ctx,
		bdcache.WithPersistence(persist),
		bdcache.WithDefaultTTL(ttl),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create bdcache: %w", err)
	}

	return &BDCache{
		cache: cache,
		ttl:   ttl,
	}, nil
}

// Get retrieves a cached response by URL.
//
//nolint:revive // interface requires 4 return values
func (c *BDCache) Get(ctx context.Context, url string) (data []byte, etag string, headers map[string]string, found bool) {
	key := urlToKey(url)
	resp, found, err := c.cache.Get(ctx, key)
	if err != nil || !found {
		return nil, "", nil, false
	}

	return resp.Data, resp.ETag, resp.Headers, true
}

// SetAsync stores a response in the cache asynchronously.
func (c *BDCache) SetAsync(ctx context.Context, url string, data []byte, etag string, headers map[string]string) error {
	return c.SetAsyncWithTTL(ctx, url, data, etag, headers, c.ttl)
}

// SetAsyncWithTTL stores a response in the cache asynchronously with a custom TTL.
func (c *BDCache) SetAsyncWithTTL(ctx context.Context, url string, data []byte, etag string, headers map[string]string, ttl time.Duration) error {
	key := urlToKey(url)
	resp := &CachedResponse{
		Data:    data,
		Headers: headers,
		ETag:    etag,
	}

	// Store in cache - we ignore errors as cache failures shouldn't break the application
	_ = c.cache.Set(ctx, key, resp, ttl) //nolint:errcheck // cache errors are non-critical
	return nil
}

// Close flushes and closes the cache.
func (c *BDCache) Close() error {
	return c.cache.Close()
}

// urlToKey converts a URL to a cache key using SHA256 hash.
// This ensures keys are filesystem-safe and uniform length.
func urlToKey(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:])
}

// Ensure BDCache implements HTTPCache.
var _ HTTPCache = (*BDCache)(nil)
