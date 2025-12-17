// Package tumblr fetches Tumblr blog profile data.
package tumblr

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

const platform = "tumblr"

// platformInfo implements profile.Platform for Tumblr.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)([a-zA-Z0-9_-]+)\.tumblr\.com`)

// Match returns true if the URL is a Tumblr profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, ".tumblr.com") {
		return false
	}
	// Skip main tumblr.com and www.tumblr.com
	if strings.Contains(lower, "://tumblr.com") || strings.Contains(lower, "://www.tumblr.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Tumblr blogs are public.
func AuthRequired() bool { return false }

// Client handles Tumblr requests.
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

// New creates a Tumblr client.
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

// Fetch retrieves a Tumblr blog profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)

	c.logger.InfoContext(ctx, "fetching tumblr profile", "url", urlStr, "username", username)

	blogURL := "https://" + username + ".tumblr.com/"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, blogURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpcache.UserAgent)

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(body, blogURL, username), nil
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

	// Extract title from og:title or page title
	ogTitle := htmlutil.OGTag(content, "og:title")
	if ogTitle != "" && !strings.Contains(strings.ToLower(ogTitle), "tumblr") {
		prof.DisplayName = ogTitle
	}

	// Extract avatar from og:image or avatar URL
	ogImage := htmlutil.OGTag(content, "og:image")
	if ogImage != "" {
		prof.AvatarURL = ogImage
	}

	// Try to find avatar in common tumblr patterns
	if prof.AvatarURL == "" {
		avatarPattern := regexp.MustCompile(`avatar[^"]*\.(?:png|jpg|gif|pnj)`)
		if m := avatarPattern.FindString(content); m != "" {
			prof.AvatarURL = "https://64.media.tumblr.com/" + m
		}
	}

	// Extract description from og:description or meta description
	ogDesc := htmlutil.OGTag(content, "og:description")
	if ogDesc != "" {
		prof.Bio = ogDesc
	}

	// Extract social links (excluding tumblr links)
	for _, link := range htmlutil.SocialLinks(content) {
		if !strings.Contains(link, "tumblr.com") {
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
