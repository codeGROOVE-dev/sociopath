// Package medium fetches Medium profile data.
package medium

import (
	"context"
	"encoding/xml"
	"errors"
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

const platform = "medium"

// Pre-compiled patterns for URL matching and extraction.
var (
	subdomainPattern  = regexp.MustCompile(`^https?://([a-z0-9_-]+)\.medium\.com/?$`)
	atUsernamePattern = regexp.MustCompile(`medium\.com/@([^/?#]+)`)
	userPathPattern   = regexp.MustCompile(`medium\.com/user/([^/?#]+)`)
	subdomainExtract  = regexp.MustCompile(`^([a-zA-Z0-9_-]+)\.medium\.com`)
	followerPattern   = regexp.MustCompile(`(\d+(?:\.\d+)?[KMk]?)\s*(?:Followers|followers)`)
	ogImagePattern    = regexp.MustCompile(
		`property=["']og:image["'][^>]+content=["']([^"']+)["']` +
			`|content=["']([^"']+)["'][^>]+property=["']og:image["']`)
)

// platformInfo implements profile.Platform for Medium.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Medium profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "medium.com/@") ||
		(strings.Contains(lower, "medium.com") && strings.Contains(lower, "/user/")) ||
		subdomainPattern.MatchString(lower)
}

// AuthRequired returns false because Medium profiles are public.
func AuthRequired() bool { return false }

// Client handles Medium requests.
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

// New creates a Medium client.
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

// rssFeed represents a Medium RSS feed.
type rssFeed struct {
	XMLName xml.Name   `xml:"rss"`
	Channel rssChannel `xml:"channel"`
}

type rssChannel struct {
	Items []rssItem `xml:"item"`
}

type rssItem struct {
	Title string `xml:"title"`
	Link  string `xml:"link"`
}

// Fetch retrieves a Medium profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	// Normalize URL
	normalizedURL := fmt.Sprintf("https://medium.com/@%s", username)
	c.logger.InfoContext(ctx, "fetching medium profile", "url", normalizedURL, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, fmt.Errorf("fetch failed: %w", err)
	}

	p, err := parseProfile(string(body), normalizedURL, username)
	if err != nil {
		return nil, err
	}

	// Fetch recent posts from RSS feed
	posts := c.fetchRecentPosts(ctx, username, 15)
	p.Posts = posts

	return p, nil
}

func parseProfile(html, url, username string) (*profile.Profile, error) {
	// Detect error pages before attempting to parse
	lowerHTML := strings.ToLower(html)
	errorPatterns := []string{
		"page not found",
		"404",
		"user not found",
		"this page is not available",
		"account suspended",
		"page doesn't exist",
	}
	for _, pattern := range errorPatterns {
		if strings.Contains(lowerHTML, pattern) {
			return nil, errors.New("profile not found (error page detected)")
		}
	}

	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract name from title or meta tags
	prof.PageTitle = htmlutil.Title(html)
	if prof.PageTitle != "" {
		// Clean up Medium title format "Name - Medium" to get display name
		if idx := strings.Index(prof.PageTitle, " - Medium"); idx != -1 {
			prof.DisplayName = strings.TrimSpace(prof.PageTitle[:idx])
		} else if idx := strings.Index(prof.PageTitle, " – Medium"); idx != -1 {
			prof.DisplayName = strings.TrimSpace(prof.PageTitle[:idx])
		}
	}

	// Detect if title is just "Medium" (error page indicator)
	if prof.PageTitle == "Medium" || prof.PageTitle == "" {
		return nil, errors.New("profile not found (invalid or missing name)")
	}

	// Extract bio/description
	prof.Bio = htmlutil.Description(html)

	// Extract avatar from og:image meta tag (handles both attribute orders)
	if matches := ogImagePattern.FindStringSubmatch(html); len(matches) > 1 {
		if matches[1] != "" {
			prof.AvatarURL = matches[1]
		} else if matches[2] != "" {
			prof.AvatarURL = matches[2]
		}
	}

	// Try to extract follower count
	if matches := followerPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["followers"] = matches[1]
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(html)

	// Filter out Medium's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "medium.com") {
			filtered = append(filtered, link)
		}
	}
	prof.SocialLinks = filtered

	// If we still don't have a name, fallback to username
	if prof.DisplayName == "" {
		prof.DisplayName = username
	}

	return prof, nil
}

func extractUsername(urlStr string) string {
	// Remove protocol for subdomain matching
	stripped := strings.TrimPrefix(strings.TrimPrefix(urlStr, "https://"), "http://")

	// Try each pattern in order of specificity
	if matches := atUsernamePattern.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}
	if matches := userPathPattern.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}
	if matches := subdomainExtract.FindStringSubmatch(stripped); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// fetchRecentPosts fetches recent posts from the Medium RSS feed.
func (c *Client) fetchRecentPosts(ctx context.Context, username string, maxItems int) []profile.Post {
	feedURL := fmt.Sprintf("https://medium.com/feed/@%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, http.NoBody)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to create RSS request", "error", err)
		return nil
	}
	req.Header.Set("User-Agent", "sociopath/1.0 (social profile aggregator)")
	req.Header.Set("Accept", "application/rss+xml, application/xml, text/xml")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to fetch RSS feed", "error", err)
		return nil
	}

	var feed rssFeed
	if err := xml.Unmarshal(body, &feed); err != nil {
		c.logger.DebugContext(ctx, "failed to parse RSS feed", "error", err)
		return nil
	}

	items := feed.Channel.Items
	if len(items) > maxItems {
		items = items[:maxItems]
	}

	var posts []profile.Post
	for _, item := range items {
		posts = append(posts, profile.Post{
			Type:  profile.PostTypeArticle,
			Title: item.Title,
			URL:   item.Link,
		})
	}

	return posts
}
