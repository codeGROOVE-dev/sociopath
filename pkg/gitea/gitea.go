// Package gitea fetches Gitea user profile data from gitea.com.
package gitea

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

const platform = "gitea"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)gitea\.com/([a-zA-Z0-9_.-]+)`)

// Match returns true if the URL is a Gitea profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "gitea.com") {
		return false
	}
	// Exclude non-profile paths
	excluded := []string{"/api/", "/explore/", "/admin/", "/user/", "/repo/"}
	for _, ex := range excluded {
		if strings.Contains(lower, ex) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Gitea profiles are public.
func AuthRequired() bool { return false }

// Client handles Gitea requests.
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

// New creates a Gitea client.
func New(_ context.Context, opts ...Option) (*Client, error) {
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

//nolint:govet // fieldalignment: struct ordering for JSON readability
type apiUser struct {
	ID          int64  `json:"id"`
	Login       string `json:"login"`
	FullName    string `json:"full_name"`
	Email       string `json:"email"`
	AvatarURL   string `json:"avatar_url"`
	Location    string `json:"location"`
	Website     string `json:"website"`
	Description string `json:"description"`
	Created     string `json:"created"`
}

// Fetch retrieves a Gitea profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching gitea profile", "url", urlStr, "username", username)

	apiURL := "https://gitea.com/api/v1/users/" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var user apiUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse gitea response: %w", err)
	}

	if user.Login == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(&user, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Login,
		Fields:   make(map[string]string),
	}

	if data.FullName != "" {
		p.DisplayName = data.FullName
	} else {
		p.DisplayName = data.Login
	}

	if data.AvatarURL != "" {
		p.AvatarURL = data.AvatarURL
	}

	if data.Location != "" {
		p.Location = data.Location
	}

	if data.Website != "" {
		p.Website = data.Website
	}

	if data.Description != "" {
		p.Bio = data.Description
	}

	if data.Created != "" {
		p.CreatedAt = data.Created
	}

	return p
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		username := matches[1]
		// Remove trailing slash or path
		if idx := strings.Index(username, "/"); idx > 0 {
			username = username[:idx]
		}
		return username
	}
	return ""
}
