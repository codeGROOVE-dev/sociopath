// Package slashdot fetches Slashdot user profile data.
package slashdot

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "slashdot"

// platformInfo implements profile.Platform for Slashdot.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)slashdot\.org/~([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Slashdot profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "slashdot.org/~") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Slashdot profiles are public.
func AuthRequired() bool { return false }

// Client handles Slashdot requests.
type Client struct {
	httpClient *http.Client
	cache      httpcache.Cacher
	logger     *slog.Logger
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache  httpcache.Cacher
	logger *slog.Logger
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache httpcache.Cacher) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates a Slashdot client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	cache := cfg.cache
	if cache == nil {
		cache = httpcache.NewNull()
	}

	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a Slashdot profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)

	c.logger.InfoContext(ctx, "fetching slashdot profile", "url", urlStr, "username", username)

	profileURL := "https://slashdot.org/~" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpcache.UserAgent)

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(body, profileURL, username), nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	prof := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		DisplayName:   username,
		Fields:        make(map[string]string),
	}

	// Extract user ID
	// Pattern: user_id: 991606
	userIDPattern := regexp.MustCompile(`user_id:\s*(\d+)`)
	if m := userIDPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["user_id"] = m[1]
	}

	// Extract karma
	// Pattern: Karma: 80 or karma level
	karmaPattern := regexp.MustCompile(`(?i)karma[^<]*?(\d+)`)
	if m := karmaPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["karma"] = m[1]
	}

	// Extract email (often obfuscated)
	emailPattern := regexp.MustCompile(`mailto:([^"]+@[^"]+)`)
	if m := emailPattern.FindStringSubmatch(content); len(m) > 1 {
		email := strings.ReplaceAll(m[1], "NOsPAM", "")
		email = strings.ReplaceAll(email, "NOSPAM", "")
		prof.Fields["email"] = email
	}

	// Extract homepage
	homepagePattern := regexp.MustCompile(`Homepage:\s*</dt>\s*<dd[^>]*>\s*<a[^>]+href="([^"]+)"`)
	if m := homepagePattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Website = m[1]
		prof.SocialLinks = append(prof.SocialLinks, m[1])
	}

	// Try simpler homepage pattern
	if prof.Website == "" {
		simpleHomepagePattern := regexp.MustCompile(`<a[^>]+href="(https?://[^"]+)"[^>]*>Homepage</a>`)
		if m := simpleHomepagePattern.FindStringSubmatch(content); len(m) > 1 {
			prof.Website = m[1]
			prof.SocialLinks = append(prof.SocialLinks, m[1])
		}
	}

	return prof
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
