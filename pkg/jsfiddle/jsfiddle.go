// Package jsfiddle fetches JSFiddle user profile data.
package jsfiddle

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

const platform = "jsfiddle"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)jsfiddle\.net/user/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a JSFiddle profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "jsfiddle.net") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because JSFiddle profiles are public.
func AuthRequired() bool { return false }

// Client handles JSFiddle requests.
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

// New creates a JSFiddle client.
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

var (
	displayNamePattern = regexp.MustCompile(`(?i)<h1[^>]*>([^<]+)</h1>`)
	avatarPattern      = regexp.MustCompile(`(?i)<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	avatarAlt          = regexp.MustCompile(`(?i)<img[^>]+src="([^"]+gravatar[^"]+)"`)
	fiddlesPattern     = regexp.MustCompile(`(?i)(\d+)\s*fiddles?`)
	locationPattern    = regexp.MustCompile(`(?i)<span[^>]*class="[^"]*location[^"]*"[^>]*>([^<]+)</span>`)
	bioPattern         = regexp.MustCompile(`(?i)<p[^>]*class="[^"]*bio[^"]*"[^>]*>([^<]+)</p>`)
	websitePattern     = regexp.MustCompile(`(?i)<a[^>]+href="(https?://[^"]+)"[^>]*class="[^"]*website[^"]*"`)
	titlePattern       = regexp.MustCompile(`(?i)<title>([^<]+)</title>`)
)

// Fetch retrieves a JSFiddle profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching jsfiddle profile", "url", urlStr, "username", username)

	profileURL := "https://jsfiddle.net/user/" + username + "/"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	content := string(body)

	// Check if profile exists
	if strings.Contains(content, "Page not found") || strings.Contains(content, "404") ||
		strings.Contains(content, "User not found") {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(content, username, urlStr), nil
}

func parseProfile(html, username, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    username,
		DisplayName: username,
		Fields:      make(map[string]string),
	}

	// Extract display name from title
	if m := titlePattern.FindStringSubmatch(html); len(m) > 1 {
		title := strings.TrimSpace(m[1])
		// Title format is usually "Username - JSFiddle"
		if idx := strings.Index(title, " - "); idx > 0 {
			name := strings.TrimSpace(title[:idx])
			if name != "" && name != username {
				p.DisplayName = name
			}
		}
	}

	if m := displayNamePattern.FindStringSubmatch(html); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" {
			p.DisplayName = name
		}
	}

	// Extract avatar
	if m := avatarPattern.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = m[1]
	} else if m := avatarAlt.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	// Extract location
	if m := locationPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract bio
	if m := bioPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Bio = strings.TrimSpace(m[1])
	}

	// Extract website
	if m := websitePattern.FindStringSubmatch(html); len(m) > 1 {
		p.Website = m[1]
	}

	// Extract fiddle count
	if m := fiddlesPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["fiddles"] = m[1]
	}

	return p
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
