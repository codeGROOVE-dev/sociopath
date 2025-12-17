// Package hackerrank fetches HackerRank user profile data.
package hackerrank

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "hackerrank"

// platformInfo implements profile.Platform for HackerRank.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)hackerrank\.com/profile/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a HackerRank profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "hackerrank.com/profile/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because HackerRank profiles are public.
func AuthRequired() bool { return false }

// Client handles HackerRank requests.
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

// New creates a HackerRank client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	cache := cfg.cache
	if cache == nil {
		cache = httpcache.NewNull()
	}

	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a HackerRank profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)

	c.logger.InfoContext(ctx, "fetching hackerrank profile", "url", urlStr, "username", username)

	profileURL := "https://www.hackerrank.com/profile/" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpcache.UserAgent)

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(body, profileURL, username), nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	prof := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		DisplayName:   username,
		Fields:        make(map[string]string),
	}

	// Extract name from og:title - format: "Stephen Morgan - rebelopsio | HackerRank"
	ogTitle := htmlutil.OGTag(content, "og:title")
	if ogTitle != "" {
		// Try to extract name before " - username | HackerRank"
		if idx := strings.Index(ogTitle, " - "); idx > 0 {
			prof.DisplayName = strings.TrimSpace(ogTitle[:idx])
		} else if idx := strings.Index(ogTitle, " | "); idx > 0 {
			prof.DisplayName = strings.TrimSpace(ogTitle[:idx])
		}
	}

	// Extract avatar from og:image
	ogImage := htmlutil.OGTag(content, "og:image")
	if ogImage != "" && strings.Contains(ogImage, "hrcdn.net") {
		prof.AvatarURL = ogImage
	}

	// Extract description from og:description
	ogDesc := htmlutil.OGTag(content, "og:description")
	if ogDesc != "" && !strings.Contains(strings.ToLower(ogDesc), "hackerrank") {
		prof.Bio = ogDesc
	}

	// Try to extract additional data from JSON embedded in page
	// Look for education info
	eduPattern := regexp.MustCompile(`"school":\s*"([^"]+)"`)
	if m := eduPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["school"] = m[1]
	}

	// Look for company info
	companyPattern := regexp.MustCompile(`"company":\s*"([^"]+)"`)
	if m := companyPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["company"] = m[1]
	}

	// Look for job title
	jobPattern := regexp.MustCompile(`"job_title":\s*"([^"]+)"`)
	if m := jobPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["job_title"] = m[1]
	}

	// Look for location/country
	countryPattern := regexp.MustCompile(`"country":\s*"([^"]+)"`)
	if m := countryPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Location = m[1]
	}

	// Look for website
	websitePattern := regexp.MustCompile(`"website":\s*"(https?://[^"]+)"`)
	if m := websitePattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Website = m[1]
		prof.SocialLinks = append(prof.SocialLinks, m[1])
	}

	// Look for LinkedIn
	linkedinPattern := regexp.MustCompile(`"linkedin_url":\s*"(https?://[^"]+)"`)
	if m := linkedinPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.SocialLinks = append(prof.SocialLinks, m[1])
	}

	// Extract social links
	for _, link := range htmlutil.SocialLinks(content) {
		if !strings.Contains(link, "hackerrank.com") {
			prof.SocialLinks = append(prof.SocialLinks, link)
		}
	}

	return prof
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
