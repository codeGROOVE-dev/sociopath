# Sociopath: General-Purpose Social Media Profile Scraper

## Overview

Refactor into a multi-package library following idiomatic Go patterns - each social media platform gets its own package with comprehensive tests.

## API Design

```go
// Top-level unified API
import "github.com/codeGROOVE-dev/sociopath"

profile, err := sociopath.Fetch(ctx, url, opts...)

// Or use platform packages directly
import "github.com/codeGROOVE-dev/sociopath/linkedin"
import "github.com/codeGROOVE-dev/sociopath/twitter"
import "github.com/codeGROOVE-dev/sociopath/mastodon"

client, err := linkedin.New(ctx)
profile, err := client.Fetch(ctx, url)
```

## Response Object (shared types package)

```go
// github.com/codeGROOVE-dev/sociopath/profile
package profile

type Profile struct {
    // Metadata
    Platform       string            // "linkedin", "twitter", "mastodon", etc.
    URL            string            // Original URL fetched
    Authenticated  bool              // Whether login cookies were used

    // Core profile data
    Username       string            // Handle/username
    Name           string            // Display name
    Bio            string            // Profile bio/description
    Location       string            // Geographic location
    Website        string            // Personal website URL

    // Platform-specific fields
    Fields         map[string]string // Additional platform-specific data

    // For further crawling
    SocialLinks    []string          // Other social media URLs detected

    // Fallback for unrecognized platforms
    Unstructured   string            // Raw markdown content (HTML->MD conversion)
}
```

## Package Structure

```
sociopath/
├── go.mod
├── sociopath.go              # Top-level Fetch() dispatcher
├── sociopath_test.go         # Integration tests
├── options.go                # WithCookies, WithBrowserCookies, etc.
│
├── profile/                  # Shared types
│   ├── profile.go            # Profile struct
│   └── profile_test.go
│
├── auth/                     # Cookie management
│   ├── auth.go               # Cookie extraction utilities
│   ├── browser.go            # Browser cookie stores (kooky)
│   ├── env.go                # Environment variable handling
│   └── auth_test.go
│
├── detect/                   # Platform detection
│   ├── detect.go             # URL -> platform mapping
│   └── detect_test.go
│
├── htmlutil/                 # Shared HTML utilities
│   ├── markdown.go           # HTML -> Markdown conversion
│   ├── extract.go            # Meta tag, title extraction
│   ├── social.go             # Social link extraction from HTML
│   └── htmlutil_test.go
│
├── linkedin/                 # LinkedIn (auth required)
│   ├── linkedin.go           # Client, Fetch
│   ├── parse.go              # HTML/JSON parsing
│   ├── linkedin_test.go      # Unit tests
│   └── testdata/             # Sample HTML responses
│       ├── profile_basic.html
│       └── profile_full.html
│
├── twitter/                  # Twitter/X (auth required)
│   ├── twitter.go            # Client, Fetch
│   ├── parse.go              # __INITIAL_STATE__ parsing
│   ├── twitter_test.go
│   └── testdata/
│       └── profile.html
│
├── mastodon/                 # Mastodon (no auth)
│   ├── mastodon.go           # Client, Fetch
│   ├── api.go                # API endpoint fetching
│   ├── parse.go              # HTML fallback parsing
│   ├── mastodon_test.go
│   └── testdata/
│       ├── api_response.json
│       └── profile.html
│
├── bluesky/                  # BlueSky (no auth)
│   ├── bluesky.go
│   ├── bluesky_test.go
│   └── testdata/
│
├── devto/                    # Dev.to (no auth)
│   ├── devto.go
│   ├── devto_test.go
│   └── testdata/
│
├── stackoverflow/            # StackOverflow (no auth)
│   ├── stackoverflow.go
│   ├── stackoverflow_test.go
│   └── testdata/
│
├── instagram/                # Instagram (auth required - stub)
│   ├── instagram.go
│   └── instagram_test.go
│
├── tiktok/                   # TikTok (auth required - stub)
│   ├── tiktok.go
│   └── tiktok_test.go
│
├── vkontakte/                # VKontakte (auth required - stub)
│   ├── vkontakte.go
│   └── vkontakte_test.go
│
├── generic/                  # Fallback HTML->Markdown
│   ├── generic.go
│   ├── generic_test.go
│   └── testdata/
│
└── cmd/
    └── sociopath/            # CLI tool
        └── main.go
```

## Platform Package Interface

Each platform package exports:

```go
package linkedin // (or twitter, mastodon, etc.)

import "github.com/codeGROOVE-dev/sociopath/profile"

// Client handles requests for this platform
type Client struct { ... }

// New creates a client (may require auth)
func New(ctx context.Context, opts ...Option) (*Client, error)

// Fetch retrieves a profile
func (c *Client) Fetch(ctx context.Context, url string) (*profile.Profile, error)

// Options
type Option func(*config)
func WithCookies(cookies map[string]string) Option
func WithBrowserCookies() Option
func WithHTTPCache(cache profile.HTTPCache) Option
func WithLogger(logger *slog.Logger) Option

// AuthRequired returns true if this platform needs authentication
func AuthRequired() bool

// Match returns true if the URL matches this platform
func Match(url string) bool
```

## Platform Support Matrix

| Package | Auth Required | Env Vars | Browser Cookies |
|---------|--------------|----------|-----------------|
| linkedin | Yes | LINKEDIN_LI_AT, LINKEDIN_JSESSIONID, LINKEDIN_LIDC | Yes |
| twitter | Yes | TWITTER_AUTH_TOKEN, TWITTER_CT0 | No |
| mastodon | No | - | - |
| bluesky | No | - | - |
| devto | No | - | - |
| stackoverflow | No | - | - |
| instagram | Yes | TBD | TBD |
| tiktok | Yes | TBD | TBD |
| vkontakte | Yes | TBD | TBD |
| generic | No | - | - |

## Implementation Order

### Phase 1: Foundation
1. `profile/` - Shared Profile type and HTTPCache interface
2. `auth/` - Cookie management utilities
3. `detect/` - URL pattern matching
4. `htmlutil/` - HTML->Markdown, meta extraction, social link detection

### Phase 2: Auth-Required Platforms (migrate existing)
5. `linkedin/` - Refactor existing code
6. `twitter/` - Import from ../twitter

### Phase 3: Public Platforms (migrate from locator)
7. `mastodon/` - Import from ../locator/pkg/social
8. `bluesky/` - Import from ../locator/pkg/social
9. `devto/` - Import from ../locator/pkg/social
10. `stackoverflow/` - Import from ../locator/pkg/social

### Phase 4: Fallback & Stubs
11. `generic/` - HTML->Markdown fallback
12. `instagram/` - Stub returning ErrAuthRequired
13. `tiktok/` - Stub returning ErrAuthRequired
14. `vkontakte/` - Stub returning ErrAuthRequired

### Phase 5: Top-Level API
15. `sociopath.go` - Unified Fetch() that dispatches to packages
16. `options.go` - Top-level option handling
17. `cmd/sociopath/` - CLI tool

## Error Types (profile package)

```go
package profile

var (
    ErrAuthRequired    = errors.New("authentication required")
    ErrNoCookies       = errors.New("no cookies available")
    ErrProfileNotFound = errors.New("profile not found")
    ErrRateLimited     = errors.New("rate limited")
)
```

## Test Strategy

Each package has:
- `testdata/` directory with sample HTML/JSON responses
- Unit tests that parse testdata files (no network)
- Table-driven tests for edge cases

Integration tests in top-level `sociopath_test.go` (skipped by default, require `-integration` flag).

## Migration Path for Locator

```go
// Before (locator/pkg/social)
content := social.Extract(ctx, data, cache, logger)

// After
import "github.com/codeGROOVE-dev/sociopath"

for kind, url := range data {
    profile, err := sociopath.Fetch(ctx, url,
        sociopath.WithHTTPCache(cache),
        sociopath.WithLogger(logger),
    )
    // Convert profile to locator's Content type
}
```
