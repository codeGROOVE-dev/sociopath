package cache

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	cache, err := New(24 * time.Hour)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = cache.Close() }() //nolint:errcheck // error ignored intentionally

	if cache.cache == nil {
		t.Error("cache.cache is nil")
	}
	if cache.ttl != 24*time.Hour {
		t.Errorf("cache.ttl = %v, want %v", cache.ttl, 24*time.Hour)
	}
}

func TestGetSet(t *testing.T) {
	// Use temporary directory for test to avoid persistence between runs
	tempDir := t.TempDir()

	cache, err := NewWithPath(1*time.Hour, tempDir)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = cache.Close() }() //nolint:errcheck // error ignored intentionally

	ctx := context.Background()
	url := "https://example.com/test"
	data := []byte("test data")
	etag := "test-etag"
	headers := map[string]string{"Content-Type": "text/html"}

	// Test Get on empty cache
	gotData, gotETag, gotHeaders, found := cache.Get(ctx, url)
	if found {
		t.Error("Get() found = true, want false for empty cache")
	}
	if gotData != nil || gotETag != "" || gotHeaders != nil {
		t.Error("Get() should return nil/empty values when not found")
	}

	// Test SetAsync
	if err := cache.SetAsync(ctx, url, data, etag, headers); err != nil {
		t.Fatalf("SetAsync() error = %v", err)
	}

	// Give it a moment for async operation
	time.Sleep(10 * time.Millisecond)

	// Test Get after Set
	gotData, gotETag, gotHeaders, found = cache.Get(ctx, url)
	if !found {
		t.Error("Get() found = false, want true after SetAsync")
	}
	if !bytes.Equal(gotData, data) {
		t.Errorf("Get() data = %q, want %q", gotData, data)
	}
	if gotETag != etag {
		t.Errorf("Get() etag = %q, want %q", gotETag, etag)
	}
	if gotHeaders["Content-Type"] != "text/html" {
		t.Errorf("Get() headers[Content-Type] = %q, want %q", gotHeaders["Content-Type"], "text/html")
	}
}

func TestURLToKey(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"simple", "https://example.com"},
		{"with path", "https://example.com/path/to/resource"},
		{"with query", "https://example.com?foo=bar&baz=qux"},
		{"with fragment", "https://example.com#fragment"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := urlToKey(tt.url)
			// Should be 64 hex characters (SHA256)
			if len(key) != 64 {
				t.Errorf("urlToKey() length = %d, want 64", len(key))
			}
			// Should be consistent
			if key != urlToKey(tt.url) {
				t.Error("urlToKey() not consistent")
			}
		})
	}
}

func TestCacheDirectory(t *testing.T) {
	cache, err := New(1 * time.Hour)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = cache.Close() }() //nolint:errcheck // error ignored intentionally //nolint:errcheck // error ignored intentionally

	// Check that cache directory was created
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir() //nolint:usetesting // can't use t.TempDir() in error fallback path
	}
	cacheDir = filepath.Join(cacheDir, "sociopath")

	info, err := os.Stat(cacheDir)
	if err != nil {
		t.Fatalf("cache directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("cache path is not a directory")
	}
}
