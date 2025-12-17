// Package pastebin fetches Pastebin user profile data.
package pastebin

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

const platform = "pastebin"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)pastebin\.com/u/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Pastebin profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "pastebin.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Pastebin profiles are public.
func AuthRequired() bool { return false }

// Client handles Pastebin requests.
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

// New creates a Pastebin client.
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
	avatarPattern   = regexp.MustCompile(`(?i)<img[^>]+class="[^"]*user_icon[^"]*"[^>]+src="([^"]+)"`)
	avatarAlt       = regexp.MustCompile(`(?i)<img[^>]+src="([^"]+)"[^>]+class="[^"]*user_icon[^"]*"`)
	joinedPattern   = regexp.MustCompile(`(?i)Joined[:\s]*</span>\s*([^<]+)<`)
	viewsPattern    = regexp.MustCompile(`(?i)Total Views[:\s]*</span>\s*([^<]+)<`)
	pastesPattern   = regexp.MustCompile(`(?i)Total Pastes[:\s]*</span>\s*([^<]+)<`)
	locationPattern = regexp.MustCompile(`(?i)Location[:\s]*</span>\s*([^<]+)<`)
	websitePattern  = regexp.MustCompile(`(?i)Website[:\s]*</span>\s*<a[^>]+href="([^"]+)"`)
)

// Fetch retrieves a Pastebin profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching pastebin profile", "url", urlStr, "username", username)

	profileURL := "https://pastebin.com/u/" + username

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
	if strings.Contains(content, "User not found") || strings.Contains(content, "does not exist") ||
		strings.Contains(content, "404 Not Found") {
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

	// Extract avatar
	if m := avatarPattern.FindStringSubmatch(html); len(m) > 1 {
		avatarURL := m[1]
		if !strings.HasPrefix(avatarURL, "http") {
			avatarURL = "https://pastebin.com" + avatarURL
		}
		p.AvatarURL = avatarURL
	} else if m := avatarAlt.FindStringSubmatch(html); len(m) > 1 {
		avatarURL := m[1]
		if !strings.HasPrefix(avatarURL, "http") {
			avatarURL = "https://pastebin.com" + avatarURL
		}
		p.AvatarURL = avatarURL
	}

	// Extract location
	if m := locationPattern.FindStringSubmatch(html); len(m) > 1 {
		loc := strings.TrimSpace(m[1])
		if loc != "" && loc != "N/A" {
			p.Location = loc
		}
	}

	// Extract website
	if m := websitePattern.FindStringSubmatch(html); len(m) > 1 {
		p.Website = m[1]
	}

	// Extract joined date
	if m := joinedPattern.FindStringSubmatch(html); len(m) > 1 {
		p.CreatedAt = strings.TrimSpace(m[1])
	}

	// Extract total views
	if m := viewsPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["total_views"] = strings.TrimSpace(m[1])
	}

	// Extract total pastes
	if m := pastesPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["total_pastes"] = strings.TrimSpace(m[1])
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
