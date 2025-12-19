// Package quay fetches Quay.io (Red Hat container registry) profile data.
package quay

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

const platform = "quay"

// platformInfo implements profile.Platform for Quay.io.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypePackage }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)quay\.io/(?:user|organization)/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Quay.io profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "quay.io/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Quay.io profiles are public.
func AuthRequired() bool { return false }

// Client handles Quay.io requests.
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

// New creates a Quay.io client.
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

// userResponse represents the Quay.io API user response.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type userResponse struct {
	Name         string         `json:"name"`
	Username     string         `json:"username"`
	Email        string         `json:"email"`
	Avatar       avatarData     `json:"avatar"`
	Organizations []orgData     `json:"organizations"`
}

// avatarData represents avatar information.
type avatarData struct {
	Name  string `json:"name"`
	Hash  string `json:"hash"`
	Color string `json:"color"`
}

// orgData represents organization membership.
type orgData struct {
	Name   string `json:"name"`
	Avatar string `json:"avatar"`
}

// reposResponse represents the Quay.io repositories list response.
type reposResponse struct {
	Repositories []repoData `json:"repositories"`
}

// repoData represents a Quay.io repository.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type repoData struct {
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsPublic    bool   `json:"is_public"`
	Kind        string `json:"kind"`
}

// Fetch retrieves a Quay.io profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching quay.io profile", "url", urlStr, "username", username)

	// Try API endpoint for user info
	apiURL := fmt.Sprintf("https://quay.io/api/v1/users/%s", username)

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

	var resp userResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse quay.io response: %w", err)
	}

	if resp.Username == "" && resp.Name == "" {
		return nil, profile.ErrProfileNotFound
	}

	prof := parseProfile(&resp, urlStr)

	// Fetch repositories
	repos := c.fetchRepos(ctx, username)
	prof.Posts = repos

	return prof, nil
}

func (c *Client) fetchRepos(ctx context.Context, namespace string) []profile.Post {
	reposURL := fmt.Sprintf("https://quay.io/api/v1/repository?namespace=%s&public=true", namespace)

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
	for _, r := range resp.Repositories {
		if !r.IsPublic {
			continue
		}

		post := profile.Post{
			Type:    profile.PostTypeRepository,
			Title:   r.Name,
			URL:     fmt.Sprintf("https://quay.io/repository/%s/%s", r.Namespace, r.Name),
			Content: r.Description,
		}
		posts = append(posts, post)
	}

	return posts
}

func parseProfile(data *userResponse, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    data.Username,
		DisplayName: data.Name,
		Fields:      make(map[string]string),
	}

	// Use Gravatar URL if available
	if data.Avatar.Hash != "" {
		p.AvatarURL = fmt.Sprintf("https://www.gravatar.com/avatar/%s", data.Avatar.Hash)
	}

	// Add organizations to groups
	for _, org := range data.Organizations {
		p.Groups = append(p.Groups, org.Name)
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
