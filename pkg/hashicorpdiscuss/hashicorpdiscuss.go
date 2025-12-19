// Package hashicorpdiscuss fetches HashiCorp Discuss forum profile data.
package hashicorpdiscuss

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

const platform = "hashicorpdiscuss"

// platformInfo implements profile.Platform for HashiCorp Discuss.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() {
	profile.RegisterWithFetcher(platformInfo{}, fetchProfile)
}

// fetchProfile is the FetchFunc for HashiCorp Discuss profiles.
func fetchProfile(ctx context.Context, url string, cfg *profile.FetcherConfig) (*profile.Profile, error) {
	var opts []Option
	if cfg != nil {
		if cfg.Logger != nil {
			opts = append(opts, WithLogger(cfg.Logger))
		}
		if c, ok := cfg.Cache.(httpcache.Cacher); ok {
			opts = append(opts, WithHTTPCache(c))
		}
	}
	client, err := New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

var usernamePattern = regexp.MustCompile(`(?i)discuss\.hashicorp\.com/u/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a HashiCorp Discuss profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "discuss.hashicorp.com/u/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Discourse forums are public.
func AuthRequired() bool { return false }

// Client handles HashiCorp Discuss requests.
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

// New creates a HashiCorp Discuss client.
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

// discourseUserResponse represents the Discourse API user response.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type discourseUserResponse struct {
	User discourseUser `json:"user"`
}

// discourseUser represents a Discourse user.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type discourseUser struct {
	ID              int    `json:"id"`
	Username        string `json:"username"`
	Name            string `json:"name"`
	AvatarTemplate  string `json:"avatar_template"`
	Bio             string `json:"bio_raw"`
	Location        string `json:"location"`
	Website         string `json:"website"`
	ProfileViewCount int   `json:"profile_view_count"`
}

// Fetch retrieves a HashiCorp Discuss profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching hashicorp discuss profile", "url", urlStr, "username", username)

	// Use Discourse API
	apiURL := fmt.Sprintf("https://discuss.hashicorp.com/u/%s.json", username)

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

	var resp discourseUserResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse discourse response: %w", err)
	}

	if resp.User.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	prof := parseProfile(&resp.User, urlStr)

	return prof, nil
}

func parseProfile(data *discourseUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    data.Username,
		DisplayName: data.Name,
		Bio:         data.Bio,
		Location:    data.Location,
		Fields:      make(map[string]string),
	}

	// Construct avatar URL from template
	if data.AvatarTemplate != "" {
		// Discourse avatar templates use {size} placeholder
		avatarURL := strings.ReplaceAll(data.AvatarTemplate, "{size}", "240")
		if !strings.HasPrefix(avatarURL, "http") {
			avatarURL = "https://discuss.hashicorp.com" + avatarURL
		}
		p.AvatarURL = avatarURL
	}

	if data.Website != "" {
		p.Website = data.Website
		p.SocialLinks = append(p.SocialLinks, data.Website)
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
