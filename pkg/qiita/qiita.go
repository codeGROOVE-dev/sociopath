// Package qiita fetches Qiita (Japanese dev platform) user profile data.
package qiita

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

const platform = "qiita"

// platformInfo implements profile.Platform for Qiita.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)qiita\.com/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Qiita user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "qiita.com/") {
		return false
	}
	// Exclude non-profile paths
	excluded := []string{"/items/", "/tags/", "/organizations/", "/search", "/api/", "/advent-calendar"}
	for _, ex := range excluded {
		if strings.Contains(lower, ex) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Qiita profiles are public.
func AuthRequired() bool { return false }

// Client handles Qiita requests.
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

// New creates a Qiita client.
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

// apiUser represents the Qiita API response.
type apiUser struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	Location          string `json:"location"`
	Organization      string `json:"organization"`
	ProfileImageURL   string `json:"profile_image_url"`
	WebsiteURL        string `json:"website_url"`
	GitHubLoginName   string `json:"github_login_name"`
	TwitterScreenName string `json:"twitter_screen_name"`
	FacebookID        string `json:"facebook_id"`
	LinkedInID        string `json:"linkedin_id"`
	FollowersCount    int    `json:"followers_count"`
	ItemsCount        int    `json:"items_count"`
}

// Fetch retrieves a Qiita profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching qiita profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://qiita.com/api/v2/users/%s", username)

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

	var user apiUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse qiita response: %w", err)
	}

	if user.ID == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(&user, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.ID,
		Fields:   make(map[string]string),
	}

	if data.Name != "" {
		p.DisplayName = data.Name
	} else {
		p.DisplayName = data.ID
	}

	if data.Description != "" {
		p.Bio = data.Description
	}

	if data.ProfileImageURL != "" {
		p.AvatarURL = data.ProfileImageURL
	}

	if data.Location != "" {
		p.Location = data.Location
	}

	// Organization/company
	if data.Organization != "" {
		p.Fields["company"] = data.Organization
	}

	// Website
	if data.WebsiteURL != "" {
		p.Website = data.WebsiteURL
		p.SocialLinks = append(p.SocialLinks, data.WebsiteURL)
	}

	// GitHub
	if data.GitHubLoginName != "" {
		githubURL := "https://github.com/" + data.GitHubLoginName
		p.Fields["github"] = githubURL
		p.SocialLinks = append(p.SocialLinks, githubURL)
	}

	// Twitter
	if data.TwitterScreenName != "" {
		twitterURL := "https://twitter.com/" + data.TwitterScreenName
		p.Fields["twitter"] = twitterURL
		p.SocialLinks = append(p.SocialLinks, twitterURL)
	}

	// Facebook
	if data.FacebookID != "" {
		facebookURL := "https://facebook.com/" + data.FacebookID
		p.Fields["facebook"] = facebookURL
		p.SocialLinks = append(p.SocialLinks, facebookURL)
	}

	// LinkedIn
	if data.LinkedInID != "" {
		linkedinURL := "https://linkedin.com/in/" + data.LinkedInID
		p.Fields["linkedin"] = linkedinURL
		p.SocialLinks = append(p.SocialLinks, linkedinURL)
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
