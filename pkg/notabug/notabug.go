// Package notabug fetches NotABug.org user profile data.
package notabug

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

const platform = "notabug"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)notabug\.org/([a-zA-Z0-9_.-]+)`)

// Match returns true if the URL is a NotABug profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "notabug.org") {
		return false
	}
	// Exclude non-profile paths
	excluded := []string{"/explore/", "/admin/", "/user/", "/api/"}
	for _, ex := range excluded {
		if strings.Contains(lower, ex) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because NotABug profiles are public.
func AuthRequired() bool { return false }

// Client handles NotABug requests.
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

// New creates a NotABug client.
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
	displayNamePattern = regexp.MustCompile(`(?i)<span[^>]*class="[^"]*header[^"]*"[^>]*>([^<]+)</span>`)
	displayNameAlt     = regexp.MustCompile(`(?i)<title>([^<]+)</title>`)
	avatarPattern      = regexp.MustCompile(`(?i)<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	avatarAlt          = regexp.MustCompile(`(?i)<img[^>]+src="([^"]+/avatar/[^"]+)"`)
	locationPattern    = regexp.MustCompile(`(?i)<i[^>]*class="[^"]*fa-map-marker[^"]*"[^>]*></i>\s*([^<]+)<`)
	websitePattern     = regexp.MustCompile(`(?i)<i[^>]*class="[^"]*fa-link[^"]*"[^>]*></i>\s*<a[^>]+href="([^"]+)"`)
	joinedPattern      = regexp.MustCompile(`(?i)<i[^>]*class="[^"]*fa-clock[^"]*"[^>]*></i>\s*Joined[:\s]*([^<]+)<`)
	reposPattern       = regexp.MustCompile(`(?i)(\d+)\s*Repositories`)
	bioPattern         = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*user-profile-bio[^"]*"[^>]*>([^<]+)</div>`)
)

// Fetch retrieves a NotABug profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching notabug profile", "url", urlStr, "username", username)

	profileURL := "https://notabug.org/" + username

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
		strings.Contains(content, "does not exist") {
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
	if m := displayNameAlt.FindStringSubmatch(html); len(m) > 1 {
		title := strings.TrimSpace(m[1])
		// Title format: "Name - NotABug.org"
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
	if m := avatarAlt.FindStringSubmatch(html); len(m) > 1 {
		avatarURL := m[1]
		if !strings.HasPrefix(avatarURL, "http") {
			avatarURL = "https://notabug.org" + avatarURL
		}
		p.AvatarURL = avatarURL
	} else if m := avatarPattern.FindStringSubmatch(html); len(m) > 1 {
		avatarURL := m[1]
		if !strings.HasPrefix(avatarURL, "http") {
			avatarURL = "https://notabug.org" + avatarURL
		}
		p.AvatarURL = avatarURL
	}

	// Extract location
	if m := locationPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract website
	if m := websitePattern.FindStringSubmatch(html); len(m) > 1 {
		p.Website = m[1]
	}

	// Extract bio
	if m := bioPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Bio = strings.TrimSpace(m[1])
	}

	// Extract joined date
	if m := joinedPattern.FindStringSubmatch(html); len(m) > 1 {
		p.CreatedAt = strings.TrimSpace(m[1])
	}

	// Extract repos count
	if m := reposPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["repositories"] = m[1]
	}

	return p
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		username := matches[1]
		// Remove trailing path
		if idx := strings.Index(username, "/"); idx > 0 {
			username = username[:idx]
		}
		return username
	}
	return ""
}
