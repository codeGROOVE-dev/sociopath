// Package tiktok provides TikTok profile fetching (requires authentication).
package tiktok

import (
	"context"
	"fmt"
	"strings"

	"github.com/codeGROOVE-dev/sociopath/auth"
	"github.com/codeGROOVE-dev/sociopath/profile"
)

const platform = "tiktok"

// Match returns true if the URL is a TikTok profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "tiktok.com/@")
}

// AuthRequired returns true because TikTok requires authentication.
func AuthRequired() bool { return true }

// Client handles TikTok requests.
type Client struct{}

// Option configures a Client.
type Option func(*config)

type config struct {
	cookies map[string]string
}

// WithCookies sets explicit cookie values.
func WithCookies(cookies map[string]string) Option {
	return func(c *config) { c.cookies = cookies }
}

// New creates a TikTok client.
// Note: TikTok scraping is not yet implemented.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}

	if len(cfg.cookies) == 0 {
		envVars := auth.EnvVarsForPlatform(platform)
		return nil, fmt.Errorf("%w: TikTok scraping requires authentication. Set %v or use WithCookies",
			profile.ErrAuthRequired, envVars)
	}

	return nil, fmt.Errorf("%w: TikTok scraping not yet implemented", profile.ErrAuthRequired)
}

// Fetch retrieves a TikTok profile.
func (*Client) Fetch(_ context.Context, _ string) (*profile.Profile, error) {
	return nil, fmt.Errorf("%w: TikTok scraping not yet implemented", profile.ErrAuthRequired)
}
