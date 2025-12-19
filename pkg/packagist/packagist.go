// Package packagist fetches Packagist (PHP package registry) profile data.
package packagist

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

const platform = "packagist"

// platformInfo implements profile.Platform for Packagist.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypePackage }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)packagist\.org/users/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Packagist profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "packagist.org/users/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Packagist profiles are public.
func AuthRequired() bool { return false }

// Client handles Packagist requests.
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

// New creates a Packagist client.
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

// apiResponse represents the Packagist API response for a user.
type apiResponse struct {
	User userData `json:"user"`
}

// userData represents Packagist user data.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type userData struct {
	Username    string         `json:"username"`
	FullName    string         `json:"fullName"`
	Email       string         `json:"email"`
	Homepage    string         `json:"homepage"`
	AvatarURL   string         `json:"avatarUrl"`
	GithubID    string         `json:"githubId"`
	GravatarID  string         `json:"gravatarId"`
	Packages    []packageData  `json:"packages"`
}

// packageData represents a Packagist package.
type packageData struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Downloads   int    `json:"downloads"`
}

// Fetch retrieves a Packagist profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching packagist profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://packagist.org/users/%s.json", username)

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
		return nil, fmt.Errorf("failed to parse packagist response: %w", err)
	}

	if resp.User.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	prof := parseProfile(&resp.User, urlStr)

	return prof, nil
}

func parseProfile(data *userData, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    data.Username,
		DisplayName: data.FullName,
		Fields:      make(map[string]string),
	}

	if data.AvatarURL != "" {
		p.AvatarURL = data.AvatarURL
	}

	if data.Homepage != "" {
		p.Website = data.Homepage
		p.SocialLinks = append(p.SocialLinks, data.Homepage)
	}

	// Add GitHub profile link if available
	if data.GithubID != "" {
		githubURL := fmt.Sprintf("https://github.com/%s", data.GithubID)
		p.SocialLinks = append(p.SocialLinks, githubURL)
		p.Fields["github"] = data.GithubID
	}

	// Convert packages to posts
	for _, pkg := range data.Packages {
		post := profile.Post{
			Type:    profile.PostTypeRepository,
			Title:   pkg.Name,
			URL:     fmt.Sprintf("https://packagist.org/packages/%s", pkg.Name),
			Content: pkg.Description,
		}
		p.Posts = append(p.Posts, post)
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
