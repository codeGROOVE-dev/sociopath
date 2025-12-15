// Platform registration and interface definitions.

package profile

import (
	"context"
	"log/slog"
	"sync"
)

// Platform defines the interface that all platform implementations must satisfy.
// Each platform package registers itself via Register() in an init() function.
type Platform interface {
	// Name returns the platform identifier (e.g., "github", "twitter").
	Name() string

	// Type returns the category of content this platform hosts.
	Type() PlatformType

	// Match returns true if the URL belongs to this platform.
	Match(url string) bool

	// AuthRequired returns true if authentication is needed to fetch profiles.
	AuthRequired() bool
}

// FetcherConfig holds configuration for creating platform fetchers.
type FetcherConfig struct {
	Cache          any               // httpcache.Cacher - use any to avoid import cycles
	Cookies        map[string]string // Platform-specific cookies
	Logger         *slog.Logger
	GitHubToken    string // GitHub API token
	BrowserCookies bool   // Whether to read cookies from browser
}

// FetchFunc is a function that fetches a profile from a URL.
// This allows platforms to register their fetch logic without requiring
// a specific client type.
type FetchFunc func(ctx context.Context, url string, cfg *FetcherConfig) (*Profile, error)

// platformEntry holds both the Platform interface and optional fetch function.
type platformEntry struct {
	platform Platform
	fetch    FetchFunc
}

// registry holds all registered platforms.
var (
	registryMu sync.RWMutex
	registry   []platformEntry
	byName     = make(map[string]*platformEntry)
)

// Register adds a platform to the global registry.
// This should be called from each platform package's init() function.
func Register(p Platform) {
	RegisterWithFetcher(p, nil)
}

// RegisterWithFetcher adds a platform with its fetch function to the global registry.
func RegisterWithFetcher(p Platform, fetch FetchFunc) {
	registryMu.Lock()
	defer registryMu.Unlock()

	name := p.Name()
	if _, exists := byName[name]; exists {
		panic("platform already registered: " + name)
	}

	entry := &platformEntry{platform: p, fetch: fetch}
	registry = append(registry, *entry)
	byName[name] = entry
}

// Platforms returns all registered platforms.
func Platforms() []Platform {
	registryMu.RLock()
	defer registryMu.RUnlock()

	result := make([]Platform, len(registry))
	for i, e := range registry {
		result[i] = e.platform
	}
	return result
}

// LookupPlatform returns the platform with the given name, or nil if not found.
func LookupPlatform(name string) Platform {
	registryMu.RLock()
	defer registryMu.RUnlock()

	if e := byName[name]; e != nil {
		return e.platform
	}
	return nil
}

// LookupFetcher returns the fetch function for the given platform name, or nil if not found.
func LookupFetcher(name string) FetchFunc {
	registryMu.RLock()
	defer registryMu.RUnlock()

	if e := byName[name]; e != nil {
		return e.fetch
	}
	return nil
}

// MatchURL returns the first platform that matches the given URL, or nil if none match.
// Platforms are checked in registration order, so order matters for overlapping patterns.
func MatchURL(url string) Platform {
	registryMu.RLock()
	defer registryMu.RUnlock()

	for _, e := range registry {
		if e.platform.Match(url) {
			return e.platform
		}
	}
	return nil
}

// Fetch finds the matching platform and fetches the profile.
// Returns ErrProfileNotFound if no platform matches or the platform has no fetcher.
func Fetch(ctx context.Context, url string, cfg *FetcherConfig) (*Profile, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	for _, e := range registry {
		if e.platform.Match(url) {
			if e.fetch == nil {
				return nil, ErrProfileNotFound
			}
			return e.fetch(ctx, url, cfg)
		}
	}
	return nil, ErrProfileNotFound
}

// TypeOf returns the platform type for a given platform name.
// Returns PlatformTypeOther for unknown platforms.
func TypeOf(name string) PlatformType {
	if p := LookupPlatform(name); p != nil {
		return p.Type()
	}
	return PlatformTypeOther
}
