// Package linkedin fetches LinkedIn user profile data.
// NOTE: LinkedIn authentication is currently broken due to their anti-scraping measures.
// This package returns minimal profiles with just the URL and username for manual verification.
package linkedin

import (
	"context"
	"log/slog"
	"regexp"
	"strings"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "linkedin"

// Match returns true if the URL is a LinkedIn profile URL.
func Match(urlStr string) bool {
	return strings.Contains(strings.ToLower(urlStr), "linkedin.com/in/")
}

// AuthRequired returns true because LinkedIn requires authentication.
// NOTE: Auth is currently broken, but we keep this true to indicate the limitation.
func AuthRequired() bool { return true }

// Client handles LinkedIn requests.
type Client struct {
	logger *slog.Logger
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cookies        map[string]string
	cache          *httpcache.Cache
	logger         *slog.Logger
	browserCookies bool
}

// WithCookies sets explicit cookie values (currently unused - auth is broken).
func WithCookies(cookies map[string]string) Option {
	return func(c *config) { c.cookies = cookies }
}

// WithHTTPCache sets the HTTP cache (currently unused - auth is broken).
func WithHTTPCache(httpCache *httpcache.Cache) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithBrowserCookies enables reading cookies from browser stores (currently unused - auth is broken).
func WithBrowserCookies() Option {
	return func(c *config) { c.browserCookies = true }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates a LinkedIn client.
// NOTE: LinkedIn authentication is currently broken. The client will return minimal profiles.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	cfg.logger.Warn("linkedin auth is broken - will return minimal profiles only")

	return &Client{
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves a LinkedIn profile.
// NOTE: LinkedIn authentication is currently broken. This returns a minimal profile
// with just the URL and username. The link is preserved for manual verification.
func (c *Client) Fetch(_ context.Context, urlStr string) (*profile.Profile, error) {
	// Normalize URL
	if !strings.HasPrefix(urlStr, "http") {
		urlStr = "https://www.linkedin.com/in/" + urlStr
	}

	username := extractPublicID(urlStr)

	c.logger.Info("linkedin auth broken - returning minimal profile", "url", urlStr, "username", username)

	// Return minimal profile with just the URL - auth is broken so we can't fetch details
	return &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}, nil
}

// EnableDebug enables debug logging (currently a no-op).
func (*Client) EnableDebug() {}

// extractPublicID extracts the username from a LinkedIn profile URL.
func extractPublicID(urlStr string) string {
	// Pattern: linkedin.com/in/username or linkedin.com/in/username/
	re := regexp.MustCompile(`linkedin\.com/in/([^/?]+)`)
	matches := re.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
