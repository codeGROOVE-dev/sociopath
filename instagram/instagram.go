// Package instagram provides Instagram profile fetching (requires authentication).
package instagram

import (
	"context"
	"fmt"
	"strings"

	"github.com/codeGROOVE-dev/sociopath/auth"
	"github.com/codeGROOVE-dev/sociopath/profile"
)

const platform = "instagram"

// Match returns true if the URL is an Instagram profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "instagram.com/")
}

// AuthRequired returns true because Instagram requires authentication.
func AuthRequired() bool { return true }

// Client handles Instagram requests.
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

// New creates an Instagram client.
// Note: Instagram scraping is not yet implemented.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}

	if len(cfg.cookies) == 0 {
		envVars := auth.EnvVarsForPlatform(platform)
		return nil, fmt.Errorf("%w: Instagram scraping requires authentication. Set %v or use WithCookies",
			profile.ErrAuthRequired, envVars)
	}

	// TODO: Implement Instagram cookie-based scraping
	return nil, fmt.Errorf("%w: Instagram scraping not yet implemented", profile.ErrAuthRequired)
}

// Fetch retrieves an Instagram profile.
func (*Client) Fetch(_ context.Context, _ string) (*profile.Profile, error) {
	return nil, fmt.Errorf("%w: Instagram scraping not yet implemented", profile.ErrAuthRequired)
}
