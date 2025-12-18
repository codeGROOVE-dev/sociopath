// Package facebook fetches Facebook profile data.
// Note: Facebook heavily restricts scraping, so limited data may be available.
package facebook

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "facebook"

// platformInfo implements profile.Platform for Facebook.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var (
	usernamePattern = regexp.MustCompile(`(?i)facebook\.com/(?:people/[^/]+/)?([a-zA-Z0-9.]+)`)
	// Facebook profile/page ID pattern - appears in URLs like /100076306083585.
	fbIDPattern = regexp.MustCompile(`/(\d{15,17})`)
	// Likes count pattern - "42 likes" or "1,234 likes".
	likesPattern = regexp.MustCompile(`(\d[\d,]*)\s+likes?`)
)

// Match returns true if the URL is a Facebook profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "facebook.com/") {
		return false
	}
	// Exclude common non-profile paths
	excluded := []string{
		"/sharer", "/share", "/dialog", "/login", "/help", "/policies",
		"/events/", "/groups/", "/pages/", "/watch/", "/marketplace/",
		"/gaming/", "/business/", "/ads/", "/privacy/", "/legal/",
		"/about/", "/settings", "/messenger", "/notes/", "/hashtag/",
	}
	for _, ex := range excluded {
		if strings.Contains(lower, ex) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false (Facebook pages are technically public,
// though content may be limited).
func AuthRequired() bool { return false }

// Client handles Facebook requests.
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

// New creates a Facebook client.
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

// Fetch retrieves a Facebook profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching facebook profile", "url", urlStr, "username", username)

	// Use mobile site - it returns actual profile data without login walls
	mobileURL := fmt.Sprintf("https://m.facebook.com/%s", username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mobileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	// Mobile user agent to match the mobile site.
	req.Header.Set("User-Agent",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "+
			"AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	// Canonical URL for the profile (www, not mobile)
	profileURL := fmt.Sprintf("https://www.facebook.com/%s", username)
	return parseProfile(string(body), username, profileURL, c.logger)
}

func parseProfile(html, username, profileURL string, logger *slog.Logger) (*profile.Profile, error) {
	p := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract display name from og:title
	p.DisplayName = htmlutil.OGTag(html, "og:title")

	// Check for profile not found - Facebook returns generic "Facebook" title
	// when a profile doesn't exist or is completely private
	pageTitle := htmlutil.Title(html)
	if p.DisplayName == "" && (pageTitle == "Facebook" || pageTitle == "") {
		logger.Debug("facebook profile not found or private", "username", username)
		return nil, profile.ErrProfileNotFound
	}

	// Clean up common Facebook suffixes
	p.DisplayName = strings.TrimSuffix(p.DisplayName, " | Facebook")
	p.DisplayName = strings.TrimSuffix(p.DisplayName, " - Facebook")
	p.DisplayName = strings.TrimSpace(p.DisplayName)

	// Extract bio/description from og:description
	rawBio := htmlutil.Description(html)

	// Extract likes count from bio (format: "Name. 42 likes. Description...")
	if matches := likesPattern.FindStringSubmatch(rawBio); len(matches) > 1 {
		p.Fields["likes"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Clean up bio - remove "Name. XX likes." prefix pattern
	p.Bio = rawBio
	if p.DisplayName != "" && strings.HasPrefix(p.Bio, p.DisplayName+".") {
		// Remove "Name. XX likes. " prefix
		p.Bio = strings.TrimPrefix(p.Bio, p.DisplayName+".")
		p.Bio = strings.TrimSpace(p.Bio)
		p.Bio = likesPattern.ReplaceAllString(p.Bio, "")
		p.Bio = strings.TrimPrefix(p.Bio, ".")
		p.Bio = strings.TrimSpace(p.Bio)
	}

	// Extract avatar from og:image (Facebook CDN URLs)
	p.AvatarURL = htmlutil.OGImage(html)

	// Extract Facebook numeric ID (useful for matching across username changes)
	if matches := fbIDPattern.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["facebook_id"] = matches[1]
	}

	// Fallback display name to username if somehow empty but profile exists
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	logger.Debug("facebook profile parsed",
		"username", username, "display_name", p.DisplayName,
		"has_avatar", p.AvatarURL != "", "likes", p.Fields["likes"])

	return p, nil
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		username := matches[1]
		// Remove query parameters and fragments
		if idx := strings.Index(username, "?"); idx > 0 {
			username = username[:idx]
		}
		if idx := strings.Index(username, "#"); idx > 0 {
			username = username[:idx]
		}
		// Skip common non-profile paths that might slip through
		lower := strings.ToLower(username)
		if lower == "profile.php" || lower == "index.php" {
			return ""
		}
		return username
	}
	return ""
}
