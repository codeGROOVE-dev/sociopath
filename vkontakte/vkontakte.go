// Package vkontakte provides VKontakte profile fetching (requires authentication).
package vkontakte

import (
	"context"
	"fmt"
	"strings"

	"github.com/codeGROOVE-dev/sociopath/auth"
	"github.com/codeGROOVE-dev/sociopath/profile"
)

const platform = "vkontakte"

// Match returns true if the URL is a VKontakte profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "vk.com/")
}

// AuthRequired returns true because VKontakte requires authentication.
func AuthRequired() bool { return true }

// Client handles VKontakte requests.
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

// New creates a VKontakte client.
// Note: VKontakte scraping is not yet implemented.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}

	if len(cfg.cookies) == 0 {
		envVars := auth.EnvVarsForPlatform(platform)
		return nil, fmt.Errorf("%w: VKontakte scraping requires authentication. Set %v or use WithCookies",
			profile.ErrAuthRequired, envVars)
	}

	return nil, fmt.Errorf("%w: VKontakte scraping not yet implemented", profile.ErrAuthRequired)
}

// Fetch retrieves a VKontakte profile.
func (*Client) Fetch(_ context.Context, _ string) (*profile.Profile, error) {
	return nil, fmt.Errorf("%w: VKontakte scraping not yet implemented", profile.ErrAuthRequired)
}
