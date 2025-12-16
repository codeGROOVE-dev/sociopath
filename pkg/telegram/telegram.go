// Package telegram fetches Telegram profile data.
package telegram

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "telegram"

// platformInfo implements profile.Platform for Telegram.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)t\.me/([a-zA-Z][a-zA-Z0-9_]{4,31})`)

// Match returns true if the URL is a Telegram profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	// Check for t.me domain specifically, not as substring (avoid matching about.me)
	if !strings.Contains(lower, "//t.me/") && !strings.HasPrefix(lower, "t.me/") {
		return false
	}
	// Exclude common non-profile paths
	if strings.Contains(lower, "/s/") || // shared links
		strings.Contains(lower, "/c/") || // channel links with message
		strings.Contains(lower, "/joinchat/") || // group join links
		strings.Contains(lower, "/addstickers/") || // sticker packs
		strings.Contains(lower, "/proxy") ||
		strings.Contains(lower, "/socks") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Telegram profiles are public.
func AuthRequired() bool { return false }

// Client handles Telegram requests.
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

// New creates a Telegram client.
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

// Fetch retrieves a Telegram profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching telegram profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://t.me/%s", username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(ctx, string(body), username, profileURL, c.logger)
}

// Patterns for extracting profile data.
var (
	ogTitlePattern = regexp.MustCompile(`(?i)<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']`)
	ogImagePattern = regexp.MustCompile(`(?i)<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']`)
	pageDescClass  = regexp.MustCompile(`class="tgme_page_description[^"]*"[^>]*>([^<]+)`)
	pageTitleClass = regexp.MustCompile(`class="tgme_page_title[^"]*"[^>]*><span[^>]*>([^<]+)</span>`)
)

func parseProfile(ctx context.Context, html, username, profileURL string, logger *slog.Logger) (*profile.Profile, error) {
	p := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract display name from og:title (Telegram puts clean name here)
	if match := ogTitlePattern.FindStringSubmatch(html); len(match) > 1 {
		p.DisplayName = strings.TrimSpace(match[1])
	}
	if p.DisplayName == "" {
		// Fallback: extract from tgme_page_title class
		if match := pageTitleClass.FindStringSubmatch(html); len(match) > 1 {
			p.DisplayName = strings.TrimSpace(match[1])
		}
	}

	// Extract bio/description
	if desc := htmlutil.Description(html); desc != "" {
		p.Bio = desc
	}
	if p.Bio == "" {
		// Fallback: extract from tgme_page_description class
		if match := pageDescClass.FindStringSubmatch(html); len(match) > 1 {
			p.Bio = strings.TrimSpace(match[1])
		}
	}

	// Extract avatar URL from og:image
	if match := ogImagePattern.FindStringSubmatch(html); len(match) > 1 {
		p.AvatarURL = match[1]
	}

	// Check if this is a valid user profile (not a bot, channel, or group)
	if p.DisplayName == "" && p.Bio == "" {
		logger.InfoContext(ctx, "telegram profile appears empty or invalid", "username", username)
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		username := matches[1]
		// Remove query parameters and fragments
		if idx := strings.Index(username, "?"); idx > 0 {
			username = username[:idx]
		}
		if idx := strings.Index(username, "#"); idx > 0 {
			username = username[:idx]
		}
		return username
	}
	return ""
}
