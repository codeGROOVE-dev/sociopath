// Package figma fetches Figma user profile data.
package figma

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

const platform = "figma"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)figma\.com/@([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Figma profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "figma.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Figma profiles are public.
func AuthRequired() bool { return false }

// Client handles Figma requests.
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

// New creates a Figma client.
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

type apiResponse struct {
	User *apiUser `json:"user"`
	Meta struct {
		Status int `json:"status"`
	} `json:"meta"`
}

type apiUser struct {
	ID       string `json:"id"`
	Handle   string `json:"handle"`
	Name     string `json:"name"`
	Bio      string `json:"bio"`
	ImageURL string `json:"img_url"`
}

// Fetch retrieves a Figma profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching figma profile", "url", urlStr, "username", username)

	apiURL := "https://www.figma.com/api/profile/handle/" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp apiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse figma response: %w", err)
	}

	if resp.User == nil || resp.User.Handle == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(resp.User, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Handle,
		Fields:   make(map[string]string),
	}

	if data.Name != "" {
		p.DisplayName = data.Name
	} else {
		p.DisplayName = data.Handle
	}

	if data.ImageURL != "" {
		p.AvatarURL = data.ImageURL
	}

	if data.Bio != "" {
		p.Bio = data.Bio
	}

	if data.ID != "" {
		p.DatabaseID = data.ID
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
