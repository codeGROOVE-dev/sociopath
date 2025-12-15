// Package disqus fetches Disqus user profile data via the public API.
package disqus

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const (
	platform = "disqus"
	// Public API key from Disqus documentation (not a secret).
	publicAPIKey = "E8Uh5l5fHZ6gD8U3KycjAIAk46f68Zw7C6eW8WSjZvCLXebZ7p0r1yrYDrLilk2F" //nolint:gosec // public API key
)

// platformInfo implements profile.Platform for Disqus.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)disqus\.com/by/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Disqus profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "disqus.com/by/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Disqus profiles are public.
func AuthRequired() bool { return false }

// Client handles Disqus requests.
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

// New creates a Disqus client.
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

// apiResponse represents the Disqus API response.
type apiResponse struct {
	Response apiUser `json:"response"`
	Code     int     `json:"code"`
}

// apiUser represents a Disqus user.
type apiUser struct {
	Avatar       apiAvatar `json:"avatar"`
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Name         string    `json:"name"`
	About        string    `json:"about"`
	Location     string    `json:"location"`
	URL          string    `json:"url"`
	ProfileURL   string    `json:"profileUrl"`
	JoinedAt     string    `json:"joinedAt"`
	NumFollowers int       `json:"numFollowers"`
	NumFollowing int       `json:"numFollowing"`
	NumPosts     int       `json:"numPosts"`
}

type apiAvatar struct {
	Large struct {
		Cache string `json:"cache"`
	} `json:"large"`
}

// postResponse represents a posts API response.
type postResponse struct {
	Response []apiPost `json:"response"`
	Code     int       `json:"code"`
}

// apiPost represents a Disqus post.
type apiPost struct {
	ID      string `json:"id"`
	Message string `json:"message"`
	Thread  struct {
		Link  string `json:"link"`
		Title string `json:"title"`
	} `json:"thread"`
}

// Fetch retrieves a Disqus profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching disqus profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://disqus.com/api/3.0/users/details.json?api_key=%s&user:username=%s", publicAPIKey, username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0 (social profile aggregator)")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp apiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse disqus response: %w", err)
	}

	if resp.Code != 0 {
		return nil, profile.ErrProfileNotFound
	}

	p := parseProfile(&resp.Response)

	// Fetch recent posts
	posts := c.fetchRecentPosts(ctx, username, 15)
	p.Posts = posts

	return p, nil
}

func parseProfile(data *apiUser) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      data.ProfileURL,
		Username: data.Username,
		Name:     data.Name,
		Fields:   make(map[string]string),
	}

	if data.About != "" {
		p.Bio = data.About
	}

	if data.Location != "" {
		p.Location = data.Location
		p.Fields["location"] = data.Location
	}

	if data.Avatar.Large.Cache != "" {
		p.AvatarURL = data.Avatar.Large.Cache
	}

	if data.JoinedAt != "" {
		if t, err := time.Parse("2006-01-02T15:04:05", data.JoinedAt); err == nil {
			p.CreatedAt = t.Format("2006-01-02")
		}
	}

	if data.NumFollowers > 0 {
		p.Fields["followers"] = strconv.Itoa(data.NumFollowers)
	}

	if data.NumPosts > 0 {
		p.Fields["posts"] = strconv.Itoa(data.NumPosts)
	}

	if data.URL != "" {
		p.SocialLinks = append(p.SocialLinks, data.URL)
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

// fetchRecentPosts fetches recent posts from the Disqus API.
func (c *Client) fetchRecentPosts(ctx context.Context, username string, maxItems int) []profile.Post {
	postsURL := fmt.Sprintf(
		"https://disqus.com/api/3.0/users/listPosts.json?api_key=%s&user:username=%s&limit=%d&related=thread",
		publicAPIKey, username, maxItems,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, postsURL, http.NoBody)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to create posts request", "error", err)
		return nil
	}
	req.Header.Set("User-Agent", "sociopath/1.0 (social profile aggregator)")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to fetch posts", "error", err)
		return nil
	}

	var resp postResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		c.logger.DebugContext(ctx, "failed to parse posts response", "error", err)
		return nil
	}

	if resp.Code != 0 {
		return nil
	}

	var posts []profile.Post
	for _, p := range resp.Response {
		post := profile.Post{
			Type: profile.PostTypeComment,
			URL:  p.Thread.Link,
		}
		if p.Thread.Title != "" {
			post.Title = p.Thread.Title
		}
		// Strip HTML from message for content preview
		content := stripHTML(p.Message)
		if len(content) > 200 {
			content = content[:200] + "..."
		}
		post.Content = content
		posts = append(posts, post)
	}

	return posts
}

// stripHTML removes HTML tags from a string.
func stripHTML(s string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	return strings.TrimSpace(re.ReplaceAllString(s, ""))
}
