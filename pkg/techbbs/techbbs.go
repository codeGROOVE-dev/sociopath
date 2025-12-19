// Package techbbs fetches TechBBS profile data.
package techbbs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "techbbs"

// platformInfo implements profile.Platform for TechBBS.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a TechBBS profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "bbs.io-tech.fi") && !strings.Contains(lower, "io-tech.fi/members") {
		return false
	}
	// Match profile URLs: /members/username.userid/
	if strings.Contains(lower, "/members/") {
		return true
	}
	return false
}

// AuthRequired returns false because TechBBS profiles are public.
func AuthRequired() bool { return false }

// Client handles TechBBS requests.
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

// New creates a TechBBS client.
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

// Fetch retrieves a TechBBS profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username, userid := extractUsernameAndID(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	// Construct normalized URL
	var normalizedURL string
	if userid != "" {
		normalizedURL = fmt.Sprintf("https://bbs.io-tech.fi/members/%s.%s/", username, userid)
	} else {
		normalizedURL = urlStr
	}

	c.logger.InfoContext(ctx, "fetching techbbs profile", "url", normalizedURL, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(string(body), normalizedURL, username)
}

func parseProfile(html, url, username string) (*profile.Profile, error) {
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract title
	prof.PageTitle = htmlutil.Title(html)

	// Extract display name from profile header
	// XenForo typically uses h1.username or similar
	namePattern := regexp.MustCompile(`(?i)<h1[^>]*class="[^"]*username[^"]*"[^>]*>\s*([^<]+)\s*</h1>`)
	if matches := namePattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.DisplayName = strings.TrimSpace(matches[1])
	}

	// Alternative: Look for username in title
	if prof.DisplayName == "" && prof.PageTitle != "" {
		// Title often contains "Username | TechBBS"
		if idx := strings.Index(prof.PageTitle, "|"); idx != -1 {
			name := strings.TrimSpace(prof.PageTitle[:idx])
			if name != "" && !strings.Contains(strings.ToLower(name), "error") {
				prof.DisplayName = name
			}
		}
	}

	// Fallback to username
	if prof.DisplayName == "" {
		prof.DisplayName = username
	}

	// Extract bio/about from profile
	bioPattern := regexp.MustCompile(`(?is)<div[^>]*class="[^"]*aboutMe[^"]*"[^>]*>(.*?)</div>`)
	if matches := bioPattern.FindStringSubmatch(html); len(matches) > 1 {
		bio := htmlutil.StripTags(matches[1])
		bio = strings.TrimSpace(bio)
		bio = regexp.MustCompile(`\s+`).ReplaceAllString(bio, " ")
		if bio != "" && len(bio) > 10 {
			prof.Bio = bio
		}
	}

	// Try meta description if no bio found
	if prof.Bio == "" {
		prof.Bio = htmlutil.Description(html)
	}

	// Extract location
	locationPattern := regexp.MustCompile(`(?is)<dt[^>]*>(?:Location|Sijainti)[^<]*</dt>\s*<dd[^>]*>(.*?)</dd>`)
	if matches := locationPattern.FindStringSubmatch(html); len(matches) > 1 {
		loc := htmlutil.StripTags(matches[1])
		loc = strings.TrimSpace(loc)
		if loc != "" {
			prof.Location = loc
		}
	}

	// Extract website/homepage
	websitePattern := regexp.MustCompile(`(?is)<dt[^>]*>(?:Website|Kotisivu)[^<]*</dt>\s*<dd[^>]*>.*?href="([^"]+)"`)
	if matches := websitePattern.FindStringSubmatch(html); len(matches) > 1 {
		website := strings.TrimSpace(matches[1])
		if website != "" && !strings.Contains(website, "bbs.io-tech.fi") {
			prof.Website = website
		}
	}

	// Extract social links from the page
	pageLinks := htmlutil.SocialLinks(html)
	for _, link := range pageLinks {
		// Skip internal links and assets
		if strings.Contains(link, "bbs.io-tech.fi") || strings.Contains(link, "io-tech.fi") ||
			strings.Contains(link, "favicon") ||
			strings.HasSuffix(link, ".ico") || strings.HasSuffix(link, ".svg") ||
			strings.HasSuffix(link, ".png") || strings.HasSuffix(link, ".jpg") {
			continue
		}
		if !slices.Contains(prof.SocialLinks, link) {
			prof.SocialLinks = append(prof.SocialLinks, link)
		}
	}

	// Extract post count
	postsPattern := regexp.MustCompile(`(?i)(\d+)\s*(?:viesti|post|message)`)
	if matches := postsPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["posts"] = matches[1]
	}

	// Extract join date
	joinPattern := regexp.MustCompile(`(?is)<dt[^>]*>(?:Joined|Liittynyt)[^<]*</dt>\s*<dd[^>]*>.*?datetime="([^"]+)"`)
	if matches := joinPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.CreatedAt = matches[1]
	}

	if prof.DisplayName == "" {
		return nil, errors.New("failed to extract profile name")
	}

	return prof, nil
}

func extractUsernameAndID(urlStr string) (username, userid string) {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")

	// Extract /members/username.userid/ pattern
	re := regexp.MustCompile(`/members/([^./?#]+)\.(\d+)/?`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 2 {
		return matches[1], matches[2]
	}

	// Try without userid
	re = regexp.MustCompile(`/members/([^/?#]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1], ""
	}

	return "", ""
}
