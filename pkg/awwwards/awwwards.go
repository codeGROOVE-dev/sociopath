// Package awwwards fetches Awwwards designer profile data.
// Note: Awwwards is project-centric, but high-profile designers do have profile pages.
package awwwards

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

const platform = "awwwards"

// platformInfo implements profile.Platform for Awwwards.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// usernamePattern matches designer profile URLs like /aristide-benoist/ or /victormwork/
var usernamePattern = regexp.MustCompile(`(?i)awwwards\.com/([a-zA-Z0-9_-]+)/?$`)

// Match returns true if the URL is an Awwwards designer profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "awwwards.com/") {
		return false
	}
	// Exclude non-profile paths
	excludePaths := []string{
		"/sites/", "/agencies/", "/collections/", "/inspiration/",
		"/academy/", "/conference/", "/jobs/", "/blog/",
		"/submission/", "/directory/", "/search/",
	}
	for _, p := range excludePaths {
		if strings.Contains(lower, p) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Awwwards profiles are public.
func AuthRequired() bool { return false }

// Client handles Awwwards requests.
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

// New creates an Awwwards client.
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

// Fetch retrieves an Awwwards designer profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	slug := extractSlug(urlStr)
	if slug == "" {
		return nil, fmt.Errorf("could not extract designer slug from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching awwwards designer profile", "url", urlStr, "slug", slug)

	// Normalize URL to profile format
	profileURL := fmt.Sprintf("https://www.awwwards.com/%s/", slug)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return c.parseProfile(ctx, string(body), profileURL, slug)
}

func (c *Client) parseProfile(_ context.Context, html, profileURL, slug string) (*profile.Profile, error) {
	p := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: slug,
		Fields:   make(map[string]string),
	}

	// Extract display name from title
	if title := htmlutil.Title(html); title != "" {
		title = strings.Split(title, " | Awwwards")[0]
		title = strings.Split(title, " - Awwwards")[0]
		title = strings.TrimSpace(title)
		if title != "" && title != slug {
			p.DisplayName = title
		}
	}

	// Extract avatar from og:image
	if avatar := htmlutil.OGImage(html); avatar != "" {
		p.AvatarURL = avatar
	}

	// Extract bio from description
	if desc := htmlutil.Description(html); desc != "" {
		p.Bio = desc
	}

	// Try to extract location/country
	locationPattern := regexp.MustCompile(`(?i)(?:from|based in|location)[^>]*>([^<]+)<`)
	if matches := locationPattern.FindStringSubmatch(html); len(matches) > 1 {
		location := htmlutil.StripTags(matches[1])
		location = strings.TrimSpace(location)
		if location != "" {
			p.Location = location
		}
	}

	// Try to extract award counts
	awardsPattern := regexp.MustCompile(`(?i)([\d,]+)\s+(?:awards?|wins?)`)
	if matches := awardsPattern.FindStringSubmatch(html); len(matches) > 1 {
		awards := strings.ReplaceAll(matches[1], ",", "")
		p.Fields["awards"] = awards
	}

	// Try to extract project/site counts
	sitesPattern := regexp.MustCompile(`(?i)([\d,]+)\s+(?:sites?|projects?)`)
	if matches := sitesPattern.FindStringSubmatch(html); len(matches) > 1 {
		sites := strings.ReplaceAll(matches[1], ",", "")
		p.Fields["projects"] = sites
	}

	// Extract social links
	p.SocialLinks = htmlutil.RelMeLinks(html)
	if len(p.SocialLinks) == 0 {
		p.SocialLinks = htmlutil.SocialLinks(html)
	}

	return p, nil
}

func extractSlug(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
