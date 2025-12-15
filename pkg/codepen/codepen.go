// Package codepen provides CodePen profile detection.
package codepen

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "codepen"

var usernamePattern = regexp.MustCompile(`(?i)codepen\.io/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a CodePen profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "codepen.io/") {
		return false
	}
	// Exclude non-profile paths
	excludePaths := []string{"/pen/", "/pens/", "/collection/", "/collections/", "/about", "/support", "/jobs", "/legal/", "/features/"}
	for _, p := range excludePaths {
		if strings.Contains(lower, p) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because CodePen profiles are public.
func AuthRequired() bool { return false }

// Client handles CodePen requests.
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

// New creates a CodePen client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a CodePen profile.
// Note: CodePen uses Cloudflare protection, so we can only extract basic info from the URL.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching codepen profile", "url", urlStr, "username", username)

	// CodePen uses Cloudflare protection, so we return a minimal profile
	// with the username extracted from the URL
	return &profile.Profile{
		Platform: platform,
		URL:      fmt.Sprintf("https://codepen.io/%s", username),
		Username: username,
		Fields:   make(map[string]string),
	}, nil
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
