// Package hahow fetches Hahow (好學校) instructor profile data.
package hahow

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "hahow"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)hahow\.in/@([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Hahow instructor profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "hahow.in") {
		return false
	}
	// Exclude non-profile paths
	if strings.Contains(lower, "/courses/") ||
		strings.Contains(lower, "/projects/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Hahow instructor profiles are public.
func AuthRequired() bool { return false }

// Client handles Hahow requests.
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

// New creates a Hahow client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

var (
	displayNamePattern = regexp.MustCompile(`(?i)<h1[^>]*class="[^"]*instructor[^"]*name[^"]*"[^>]*>([^<]+)</h1>`)
	titlePattern       = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*instructor[^"]*title[^"]*"[^>]*>([^<]+)</div>`)
	bioPattern         = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*instructor[^"]*bio[^"]*"[^>]*>([^<]+)</div>`)
	avatarPattern      = regexp.MustCompile(`(?i)<img[^>]+class="[^"]*instructor[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	coursesPattern     = regexp.MustCompile(`(?i)課程\s*<span[^>]*>(\d+)</span>`)
	studentsPattern    = regexp.MustCompile(`(?i)學生\s*<span[^>]*>(\d+)</span>`)
)

// Fetch retrieves a Hahow instructor profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching hahow profile", "url", urlStr, "username", username)

	profileURL := "https://hahow.in/@" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("DNT", "1")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	content := string(body)

	// Check if profile exists
	if htmlutil.IsNotFound(content) {
		return nil, profile.ErrProfileNotFound
	}

	// Requirement: username must be present on page to avoid "infinite loading" false positives
	if !strings.Contains(content, "@"+username) && !strings.Contains(content, username) {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(content, username, urlStr), nil
}

func parseProfile(htmlContent, username, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract display name
	if m := displayNamePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		name := strings.TrimSpace(html.UnescapeString(m[1]))
		if name != "" && !htmlutil.IsGenericTitle(name) {
			p.DisplayName = name
		}
	}

	// If no display name found, it might be a generic page
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	// Extract title/role
	if m := titlePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		title := strings.TrimSpace(html.UnescapeString(m[1]))
		if title != "" {
			p.Fields["title"] = title
		}
	}

	// Extract bio
	if m := bioPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		bioText := strings.TrimSpace(html.UnescapeString(m[1]))
		if bioText != "" {
			p.Bio = bioText
		}
	}

	// Extract avatar
	if m := avatarPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		avatarURL := m[1]
		if !strings.Contains(avatarURL, "default") {
			// Make absolute URL if needed
			if strings.HasPrefix(avatarURL, "//") {
				avatarURL = "https:" + avatarURL
			} else if strings.HasPrefix(avatarURL, "/") {
				avatarURL = "https://hahow.in" + avatarURL
			}
			p.AvatarURL = avatarURL
		}
	}

	// Extract course count
	if m := coursesPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		p.Fields["courses"] = m[1]
	}

	// Extract student count
	if m := studentsPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		p.Fields["students"] = m[1]
	}

	// Extract social media links
	socialLinks := htmlutil.SocialLinks(htmlContent)
	if len(socialLinks) > 0 {
		p.SocialLinks = socialLinks
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
