// Package scratch fetches user profiles from scratch.mit.edu.
package scratch

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

const platform = "scratch"

// platformInfo implements profile.Platform for Scratch.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return false }

func init() { profile.Register(platformInfo{}) }

var urlPattern = regexp.MustCompile(`(?i)scratch\.mit\.edu/users/([^/?#]+)`)

// Match returns true if the URL is a scratch.mit.edu user profile.
func Match(url string) bool {
	return urlPattern.MatchString(url)
}

// ExtractUsername returns the username from a scratch.mit.edu URL.
func ExtractUsername(url string) string {
	m := urlPattern.FindStringSubmatch(url)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// apiResponse represents the scratch API response.
//
//nolint:govet // field alignment not critical for JSON parsing
type apiResponse struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	History  struct {
		Joined string `json:"joined"`
	} `json:"history"`
	Profile struct {
		Status  string `json:"status"`
		Bio     string `json:"bio"`
		Country string `json:"country"`
	} `json:"profile"`
}

// Client fetches scratch.mit.edu profiles.
type Client struct {
	httpClient *http.Client
	cache      httpcache.Cacher
	logger     *slog.Logger
}

// Option configures the Client.
type Option func(*config)

type config struct {
	cache  httpcache.Cacher
	logger *slog.Logger
}

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) { c.logger = l }
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(cache httpcache.Cacher) Option {
	return func(c *config) { c.cache = cache }
}

// New creates a new scratch client.
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

// Fetch retrieves a scratch.mit.edu user profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := ExtractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("invalid scratch URL: %s", urlStr)
	}

	c.logger.Info("fetching scratch profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://api.scratch.mit.edu/users/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, fmt.Errorf("fetch scratch API: %w", err)
	}

	var resp apiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse scratch API response: %w", err)
	}

	p := &profile.Profile{
		Platform:   platform,
		URL:        fmt.Sprintf("https://scratch.mit.edu/users/%s", resp.Username),
		Username:   resp.Username,
		DatabaseID: strconv.Itoa(resp.ID),
		// Don't include SocialLinks - scratch profiles link to unrelated content
	}

	if resp.Profile.Country != "" {
		p.Location = resp.Profile.Country
	}

	if resp.Profile.Bio != "" {
		p.Bio = strings.TrimSpace(resp.Profile.Bio)
	}

	if resp.History.Joined != "" {
		p.CreatedAt = resp.History.Joined
	}

	return p, nil
}
