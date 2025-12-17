// Package asciinema fetches asciinema user profile data.
package asciinema

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

const platform = "asciinema"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)asciinema\.org/~([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is an asciinema profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "asciinema.org") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because asciinema profiles are public.
func AuthRequired() bool { return false }

// Client handles asciinema requests.
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

// New creates an asciinema client.
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
	avatarAlt          = regexp.MustCompile(`(?i)<img[^>]+src="([^"]+)"[^>]+class="[^"]*avatar[^"]*"`)
	asciicastsPattern  = regexp.MustCompile(`(?i)(\d+)\s*asciicasts?`)
	joinedPattern      = regexp.MustCompile(`(?i)Joined\s+([^<]+)<`)
)

// Fetch retrieves an asciinema profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching asciinema profile", "url", urlStr, "username", username)

	profileURL := "https://asciinema.org/~" + username

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
	if strings.Contains(content, "Page not found") || strings.Contains(content, "404 Not Found") {
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

	// Extract display name
	if m := displayNamePattern.FindStringSubmatch(html); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" && name != "~"+username {
			p.DisplayName = name
		}
	}

	// Extract avatar
	if m := avatarPattern.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = m[1]
	} else if m := avatarAlt.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	// Ensure avatar URL is absolute
	if p.AvatarURL != "" && !strings.HasPrefix(p.AvatarURL, "http") {
		p.AvatarURL = "https://asciinema.org" + p.AvatarURL
	}

	// Extract asciicast count
	if m := asciicastsPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["asciicasts"] = m[1]
	}

	// Extract joined date
	if m := joinedPattern.FindStringSubmatch(html); len(m) > 1 {
		p.CreatedAt = strings.TrimSpace(m[1])
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
