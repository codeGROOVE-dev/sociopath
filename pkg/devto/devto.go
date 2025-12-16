// Package devto fetches Dev.to user profile data.
package devto

import (
	"context"
	"crypto/tls"
	"encoding/json"
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

const platform = "devto"

// platformInfo implements profile.Platform for Dev.to.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Dev.to profile URL.
func Match(urlStr string) bool {
	return strings.Contains(strings.ToLower(urlStr), "dev.to/")
}

// AuthRequired returns false because Dev.to profiles are public.
func AuthRequired() bool { return false }

// Client handles Dev.to requests.
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

// New creates a Dev.to client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves a Dev.to profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching devto profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	p := parseHTML(body, urlStr, username)

	// Fetch recent articles via API
	posts, lastActive := c.fetchArticles(ctx, username, 50)
	p.Posts = posts
	if lastActive != "" && lastActive > p.UpdatedAt {
		p.UpdatedAt = lastActive
	}

	return p, nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	p := &profile.Profile{ //nolint:varnamelen // p for profile is idiomatic

		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Extract name from crayons-title h1
	namePattern := regexp.MustCompile(`<h1[^>]*class="[^"]*crayons-title[^"]*"[^>]*>\s*([^<]+)\s*</h1>`)
	if m := namePattern.FindStringSubmatch(content); len(m) > 1 {
		p.DisplayName = strings.TrimSpace(html.UnescapeString(m[1]))
	}

	// Extract avatar URL from profile image
	avatarPattern := regexp.MustCompile(`<img[^>]+class="[^"]*crayons-avatar[^"]*"[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(content); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	// Fallback to og:title
	if p.DisplayName == "" {
		title := htmlutil.Title(content)
		if idx := strings.Index(title, " - DEV"); idx > 0 {
			p.DisplayName = strings.TrimSpace(title[:idx])
		}
	}

	// Extract bio from meta description
	p.Bio = htmlutil.Description(content)

	// Extract location - look for <title>Location</title> followed by <span>location</span>
	locPattern := regexp.MustCompile(`(?s)<title[^>]*>Location</title>.*?</svg>\s*<span>\s*([^<]+?)\s*</span>`)
	if m := locPattern.FindStringSubmatch(content); len(m) > 1 {
		loc := strings.TrimSpace(html.UnescapeString(m[1]))
		if loc != "" && !strings.Contains(strings.ToLower(loc), "joined") {
			p.Location = loc
		}
	}

	// Extract joined date
	joinedPattern := regexp.MustCompile(`<time\s+datetime="([^"]+)"[^>]*>([^<]+)</time>`)
	if m := joinedPattern.FindStringSubmatch(content); len(m) > 2 {
		p.CreatedAt = m[1] // ISO datetime format
	}

	// Extract work/employment - look for <p>Work</p> followed by value
	workPattern := regexp.MustCompile(`<strong[^>]*>\s*<p>Work</p>\s*</strong>\s*<p[^>]*>\s*<p>([^<]+)</p>`)
	if m := workPattern.FindStringSubmatch(content); len(m) > 1 {
		work := strings.TrimSpace(html.UnescapeString(m[1]))
		if work != "" {
			p.Fields["work"] = work
		}
	}

	// Extract website - look for profile-header__meta__item link
	websitePattern := regexp.MustCompile(`<a\s+href=["'](https?://[^"']+)["'][^>]*class="[^"]*profile-header__meta__item[^"]*"`)
	if m := websitePattern.FindStringSubmatch(content); len(m) > 1 {
		website := m[1]
		// Filter out social media URLs
		if !strings.Contains(website, "twitter.com") &&
			!strings.Contains(website, "x.com") &&
			!strings.Contains(website, "github.com") &&
			!strings.Contains(website, "linkedin.com") {
			p.Website = website
		}
	}

	// Extract Twitter
	twitterPattern := regexp.MustCompile(`<a[^>]+href=["'](https?://(?:twitter\.com|x\.com)/[^"']+)["']`)
	if m := twitterPattern.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["twitter"] = m[1]
	}

	// Extract GitHub
	githubPattern := regexp.MustCompile(`<a[^>]+href=["'](https?://github\.com/[^"']+)["']`)
	if m := githubPattern.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["github"] = m[1]
	}

	p.SocialLinks = htmlutil.SocialLinks(content)

	return p
}

func (c *Client) fetchArticles(ctx context.Context, username string, limit int) (posts []profile.Post, lastActive string) {
	apiURL := fmt.Sprintf("https://dev.to/api/articles?username=%s&per_page=%d", username, limit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sociopath/1.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, ""
	}

	var articles []struct {
		Title       string `json:"title"`
		PublishedAt string `json:"published_at"`
		URL         string `json:"url"`
	}

	if err := json.Unmarshal(body, &articles); err != nil {
		return nil, ""
	}

	for i, a := range articles {
		if a.Title == "" {
			continue
		}
		posts = append(posts, profile.Post{
			Type:  profile.PostTypeArticle,
			Title: a.Title,
			URL:   a.URL,
		})
		// First article is the most recent
		if i == 0 && a.PublishedAt != "" {
			lastActive = a.PublishedAt
		}
	}

	return posts, lastActive
}

func extractUsername(urlStr string) string {
	if idx := strings.Index(urlStr, "dev.to/"); idx != -1 {
		username := urlStr[idx+len("dev.to/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}
	return ""
}
