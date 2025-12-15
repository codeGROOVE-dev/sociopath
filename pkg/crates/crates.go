// Package crates fetches crates.io (Rust package registry) profile data.
package crates

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

const platform = "crates"

// platformInfo implements profile.Platform for Crates.io.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypePackage }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)crates\.io/users/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a crates.io user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "crates.io/users/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because crates.io profiles are public.
func AuthRequired() bool { return false }

// Client handles crates.io requests.
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

// New creates a crates.io client.
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

// apiResponse represents the crates.io API response.
type apiResponse struct {
	User userData `json:"user"`
}

type userData struct {
	Login  string `json:"login"`
	Name   string `json:"name"`
	Avatar string `json:"avatar"`
	URL    string `json:"url"` // Often a GitHub URL
	ID     int    `json:"id"`
}

// Fetch retrieves a crates.io profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching crates.io profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://crates.io/api/v1/users/%s", username)

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
		return nil, fmt.Errorf("failed to parse crates.io response: %w", err)
	}

	if resp.User.Login == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(&resp.User, urlStr), nil
}

func parseProfile(data *userData, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Login,
		Name:     data.Name,
		Fields:   make(map[string]string),
	}

	if data.Avatar != "" {
		p.AvatarURL = data.Avatar
	}

	// The URL field often contains a GitHub profile URL
	if data.URL != "" {
		p.Website = data.URL
		p.SocialLinks = append(p.SocialLinks, data.URL)
		// Check if it's a GitHub URL
		if strings.Contains(strings.ToLower(data.URL), "github.com") {
			p.Fields["github"] = data.URL
		}
	}

	if p.Name == "" {
		p.Name = p.Username
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
