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
	"strconv"
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

	// Start with API data (more reliable)
	p, err := c.fetchUserAPI(ctx, username, urlStr)
	if err != nil {
		return nil, err
	}

	// Fetch HTML for additional fields not in API
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err == nil {
		req.Header.Set("User-Agent", "sociopath/1.0")
		if body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger); err == nil {
			enrichFromHTML(p, body)
		}
	}

	// Fetch recent articles via API
	posts, lastActive := c.fetchArticles(ctx, username, 50)
	p.Posts = posts
	if lastActive != "" && lastActive > p.UpdatedAt {
		p.UpdatedAt = lastActive
	}

	return p, nil
}

// fetchUserAPI retrieves user data from Dev.to API.
func (c *Client) fetchUserAPI(ctx context.Context, username, urlStr string) (*profile.Profile, error) {
	apiURL := fmt.Sprintf("https://dev.to/api/users/by_username?url=%s", username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sociopath/1.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var user struct {
		Username        string `json:"username"`
		Name            string `json:"name"`
		TwitterUsername string `json:"twitter_username"`
		GitHubUsername  string `json:"github_username"`
		Summary         string `json:"summary"`
		Location        string `json:"location"`
		WebsiteURL      string `json:"website_url"`
		JoinedAt        string `json:"joined_at"`
		ProfileImage    string `json:"profile_image"`
		ID              int    `json:"id"`
	}

	if err := json.Unmarshal(body, &user); err != nil {
		return nil, profile.ErrProfileNotFound
	}

	// Check if we got valid user data (ID > 0 means user exists)
	if user.ID == 0 {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		DisplayName:   user.Name,
		Bio:           user.Summary,
		Location:      user.Location,
		Website:       user.WebsiteURL,
		AvatarURL:     user.ProfileImage,
		Fields:        make(map[string]string),
	}

	if user.JoinedAt != "" {
		p.CreatedAt = user.JoinedAt
	}

	if user.TwitterUsername != "" {
		p.Fields["twitter"] = fmt.Sprintf("https://twitter.com/%s", user.TwitterUsername)
	}
	if user.GitHubUsername != "" {
		p.Fields["github"] = fmt.Sprintf("https://github.com/%s", user.GitHubUsername)
	}
	if user.ID > 0 {
		p.Fields["devto_id"] = strconv.Itoa(user.ID)
	}

	return p, nil
}

// enrichFromHTML adds additional data from HTML that isn't in the API.
func enrichFromHTML(p *profile.Profile, data []byte) {
	content := string(data)

	// Extract work/employment - look for Work section
	workPattern := regexp.MustCompile(`(?s)<p[^>]*>\s*Work\s*</p>\s*</[^>]+>\s*<p[^>]*>\s*<p>([^<]+)</p>`)
	if m := workPattern.FindStringSubmatch(content); len(m) > 1 {
		work := strings.TrimSpace(html.UnescapeString(m[1]))
		if work != "" {
			p.Fields["work"] = work
		}
	}

	// Alternate work pattern
	if p.Fields["work"] == "" {
		workPattern2 := regexp.MustCompile(`(?s)Work</p>\s*</strong>\s*<p[^>]*>\s*<p>([^<]+)</p>`)
		if m := workPattern2.FindStringSubmatch(content); len(m) > 1 {
			work := strings.TrimSpace(html.UnescapeString(m[1]))
			if work != "" {
				p.Fields["work"] = work
			}
		}
	}

	// Add social links from HTML
	if len(p.SocialLinks) == 0 {
		p.SocialLinks = htmlutil.SocialLinks(content)
	}
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
