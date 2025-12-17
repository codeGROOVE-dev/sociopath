// Package observablehq fetches Observable HQ user profile data.
package observablehq

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "observablehq"

// platformInfo implements profile.Platform for Observable HQ.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)observablehq\.com/@([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is an Observable HQ profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "observablehq.com/@") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Observable HQ profiles are public.
func AuthRequired() bool { return false }

// Client handles Observable HQ requests.
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

// New creates an Observable HQ client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	cache := cfg.cache
	if cache == nil {
		cache = httpcache.NewNull()
	}

	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves an Observable HQ profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)

	c.logger.InfoContext(ctx, "fetching observablehq profile", "url", urlStr, "username", username)

	profileURL := "https://observablehq.com/@" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpcache.UserAgent)

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(body, profileURL, username), nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	prof := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		DisplayName:   username,
		Fields:        make(map[string]string),
	}

	// Extract name from og:title - format: "Liz Fong-Jones"
	ogTitle := htmlutil.OGTag(content, "og:title")
	if ogTitle != "" && !strings.Contains(strings.ToLower(ogTitle), "observable") {
		prof.DisplayName = strings.TrimSpace(ogTitle)
	}

	// Extract avatar from og:image
	ogImage := htmlutil.OGTag(content, "og:image")
	if ogImage != "" && strings.Contains(ogImage, "avatar") {
		prof.AvatarURL = ogImage
	}

	// Try to find avatar in other patterns
	if prof.AvatarURL == "" {
		avatarPattern := regexp.MustCompile(`https://avatars\.observableusercontent\.com/avatar/[a-f0-9]+`)
		if m := avatarPattern.FindString(content); m != "" {
			prof.AvatarURL = m
		}
	}

	// Extract bio from og:description
	ogDesc := htmlutil.OGTag(content, "og:description")
	if ogDesc != "" && !strings.Contains(ogDesc, "doesn't have any") {
		prof.Bio = ogDesc
	}

	// Extract social links
	for _, link := range htmlutil.SocialLinks(content) {
		if !strings.Contains(link, "observablehq.com") {
			prof.SocialLinks = append(prof.SocialLinks, link)
		}
	}

	return prof
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
