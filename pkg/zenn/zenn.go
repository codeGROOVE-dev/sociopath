// Package zenn fetches Zenn (Japanese dev platform) user profile data.
package zenn

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "zenn"

var usernamePattern = regexp.MustCompile(`(?i)zenn\.dev/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Zenn user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "zenn.dev/") {
		return false
	}
	// Exclude non-profile paths
	excluded := []string{"/articles/", "/books/", "/scraps/", "/topics/", "/search", "/api/"}
	for _, ex := range excluded {
		if strings.Contains(lower, ex) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Zenn profiles are public.
func AuthRequired() bool { return false }

// Client handles Zenn requests.
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

// New creates a Zenn client.
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

// apiResponse represents the Zenn API response wrapper.
type apiResponse struct {
	User *apiUser `json:"user"`
}

// apiUser represents the Zenn user data.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type apiUser struct {
	ID              int    `json:"id"`
	Username        string `json:"username"`
	Name            string `json:"name"`
	AvatarURL       string `json:"avatar_url"`
	Bio             string `json:"bio"`
	GitHubUsername  string `json:"github_username"`
	TwitterUsername string `json:"twitter_username"`
	WebsiteURL      string `json:"website_url"`
	HatenaID        string `json:"hatena_id"`
	FollowerCount   int    `json:"follower_count"`
	ArticlesCount   int    `json:"articles_count"`
}

// Fetch retrieves a Zenn profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching zenn profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://zenn.dev/api/users/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp apiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse zenn response: %w", err)
	}

	if resp.User == nil || resp.User.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(resp.User, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Username,
		Fields:   make(map[string]string),
	}

	if data.Name != "" {
		p.Name = data.Name
	} else {
		p.Name = data.Username
	}

	if data.Bio != "" {
		p.Bio = data.Bio
	}

	if data.AvatarURL != "" {
		p.AvatarURL = data.AvatarURL
	}

	// Website
	if data.WebsiteURL != "" {
		p.Website = data.WebsiteURL
		p.SocialLinks = append(p.SocialLinks, data.WebsiteURL)
	}

	// GitHub
	if data.GitHubUsername != "" {
		githubURL := "https://github.com/" + data.GitHubUsername
		p.Fields["github"] = githubURL
		p.SocialLinks = append(p.SocialLinks, githubURL)
	}

	// Twitter
	if data.TwitterUsername != "" {
		twitterURL := "https://twitter.com/" + data.TwitterUsername
		p.Fields["twitter"] = twitterURL
		p.SocialLinks = append(p.SocialLinks, twitterURL)
	}

	// Hatena (Japanese blogging platform)
	if data.HatenaID != "" {
		hatenaURL := "https://profile.hatena.ne.jp/" + data.HatenaID
		p.Fields["hatena"] = hatenaURL
		p.SocialLinks = append(p.SocialLinks, hatenaURL)
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
