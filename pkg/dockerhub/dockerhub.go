// Package dockerhub fetches Docker Hub profile data.
package dockerhub

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

const platform = "dockerhub"

// platformInfo implements profile.Platform for Docker Hub.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypePackage }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)hub\.docker\.com/[ur]/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Docker Hub profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "hub.docker.com/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Docker Hub profiles are public.
func AuthRequired() bool { return false }

// Client handles Docker Hub requests.
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

// New creates a Docker Hub client.
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

// apiResponse represents the Docker Hub API response.
type apiResponse struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	FullName    string `json:"full_name"`
	Location    string `json:"location"`
	Company     string `json:"company"`
	ProfileURL  string `json:"profile_url"`
	DateJoined  string `json:"date_joined"`
	GravatarURL string `json:"gravatar_url"`
}

// reposResponse represents the Docker Hub repos API response.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type reposResponse struct {
	Count   int    `json:"count"`
	Results []repo `json:"results"`
}

// repo represents a Docker Hub repository.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type repo struct {
	Name           string `json:"name"`
	Namespace      string `json:"namespace"`
	Description    string `json:"description"`
	PullCount      int    `json:"pull_count"`
	StarCount      int    `json:"star_count"`
	LastUpdated    string `json:"last_updated"`
	DateRegistered string `json:"date_registered"`
}

// Fetch retrieves a Docker Hub profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching docker hub profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://hub.docker.com/v2/users/%s/", username)

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
		return nil, fmt.Errorf("failed to parse docker hub response: %w", err)
	}

	if resp.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	prof := parseProfile(&resp, urlStr)

	// Fetch repositories
	repos := c.fetchRepos(ctx, username)
	prof.Posts = repos

	return prof, nil
}

func (c *Client) fetchRepos(ctx context.Context, username string) []profile.Post {
	reposURL := fmt.Sprintf("https://hub.docker.com/v2/repositories/%s/", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reposURL, http.NoBody)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil
	}

	var resp reposResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil
	}

	var posts []profile.Post
	for _, r := range resp.Results {
		post := profile.Post{
			Type:  profile.PostTypeRepository,
			Title: r.Name,
			URL:   fmt.Sprintf("https://hub.docker.com/r/%s/%s", r.Namespace, r.Name),
		}

		// Build content with description and stats
		var parts []string
		if r.Description != "" {
			parts = append(parts, r.Description)
		}
		if r.PullCount > 0 {
			parts = append(parts, fmt.Sprintf("%d pulls", r.PullCount))
		}
		if r.StarCount > 0 {
			parts = append(parts, fmt.Sprintf("%d stars", r.StarCount))
		}
		if len(parts) > 0 {
			post.Content = strings.Join(parts, " | ")
		}

		// Format date as YYYY-MM-DD
		if r.LastUpdated != "" && len(r.LastUpdated) >= 10 {
			post.Date = r.LastUpdated[:10]
		}
		posts = append(posts, post)
	}

	return posts
}

func parseProfile(data *apiResponse, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    data.Username,
		DisplayName: data.FullName,
		Location:    data.Location,
		Fields:      make(map[string]string),
	}

	if data.GravatarURL != "" {
		p.AvatarURL = data.GravatarURL
	}

	if data.Company != "" {
		p.Fields["company"] = data.Company
	}

	if data.ProfileURL != "" {
		p.Website = data.ProfileURL
		p.SocialLinks = append(p.SocialLinks, data.ProfileURL)
	}

	if p.DisplayName == "" {
		p.DisplayName = p.Username
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
