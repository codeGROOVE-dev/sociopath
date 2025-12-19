// Package cncfcommunity fetches CNCF Community platform profile data.
package cncfcommunity

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

const platform = "cncfcommunity"

// platformInfo implements profile.Platform for CNCF Community.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() {
	profile.RegisterWithFetcher(platformInfo{}, fetchProfile)
}

// fetchProfile is the FetchFunc for CNCF Community profiles.
func fetchProfile(ctx context.Context, url string, cfg *profile.FetcherConfig) (*profile.Profile, error) {
	var opts []Option
	if cfg != nil {
		if cfg.Logger != nil {
			opts = append(opts, WithLogger(cfg.Logger))
		}
		if c, ok := cfg.Cache.(httpcache.Cacher); ok {
			opts = append(opts, WithHTTPCache(c))
		}
	}
	client, err := New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

var usernamePattern = regexp.MustCompile(`(?i)community\.cncf\.io/u/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a CNCF Community profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "community.cncf.io/u/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because CNCF Community profiles are public.
func AuthRequired() bool { return false }

// Client handles CNCF Community requests.
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

// New creates a CNCF Community client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
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
	namePattern     = regexp.MustCompile(`<h1[^>]*>([^<]+)</h1>`)
	bioPattern      = regexp.MustCompile(`(?s)<p class="bio[^"]*">([^<]+)</p>`)
	locationPattern = regexp.MustCompile(`(?s)location[^>]*>([^<]+)</`)
	websitePattern  = regexp.MustCompile(`<a[^>]+href="(https?://[^"]+)"[^>]*>Website</a>`)
	rolePattern     = regexp.MustCompile(`(?s)<div[^>]*class="[^"]*role[^"]*"[^>]*>([^<]+)</div>`)
	avatarPattern   = regexp.MustCompile(`<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	twitterPattern  = regexp.MustCompile(`@([a-zA-Z0-9_]+)`)
	linkedinPattern = regexp.MustCompile(`linkedin\.com/in/([a-zA-Z0-9_-]+)`)
)

// Fetch retrieves a CNCF Community profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	userID := extractUserID(urlStr)
	if userID == "" {
		return nil, fmt.Errorf("could not extract user ID from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching cncf community profile", "url", urlStr, "user_id", userID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	prof := parseHTML(string(body), urlStr, userID)

	return prof, nil
}

func parseHTML(html, urlStr, userID string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      urlStr,
		Username: userID,
		Fields:   make(map[string]string),
	}

	// Extract name from title or h1
	if title := htmlutil.Title(html); title != "" {
		name := strings.TrimSuffix(title, " | CNCF")
		name = strings.TrimSpace(name)
		p.DisplayName = name
	}

	// Try to extract name from h1 if not found in title
	if p.DisplayName == "" || p.DisplayName == userID {
		if m := namePattern.FindStringSubmatch(html); len(m) > 1 {
			p.DisplayName = strings.TrimSpace(m[1])
		}
	}

	// Extract bio
	if m := bioPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Bio = strings.TrimSpace(m[1])
	}

	// Extract location
	if m := locationPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract website
	if m := websitePattern.FindStringSubmatch(html); len(m) > 1 {
		p.Website = m[1]
		p.SocialLinks = append(p.SocialLinks, m[1])
	}

	// Extract role/title
	if m := rolePattern.FindStringSubmatch(html); len(m) > 1 {
		role := strings.TrimSpace(m[1])
		if role != "" {
			p.Fields["role"] = role
		}
	}

	// Extract avatar
	if m := avatarPattern.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	// Extract social media links from bio and content
	// Twitter
	if m := twitterPattern.FindStringSubmatch(html); len(m) > 1 {
		twitterURL := fmt.Sprintf("https://twitter.com/%s", m[1])
		p.SocialLinks = append(p.SocialLinks, twitterURL)
	}

	// LinkedIn
	if m := linkedinPattern.FindStringSubmatch(html); len(m) > 1 {
		linkedinURL := fmt.Sprintf("https://linkedin.com/in/%s", m[1])
		p.SocialLinks = append(p.SocialLinks, linkedinURL)
	}

	// Extract other social links using htmlutil
	for _, link := range htmlutil.SocialLinks(html) {
		if !contains(p.SocialLinks, link) {
			p.SocialLinks = append(p.SocialLinks, link)
		}
	}

	if p.DisplayName == "" {
		p.DisplayName = userID
	}

	return p
}

func extractUserID(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
