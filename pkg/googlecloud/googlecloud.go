// Package googlecloud fetches Google Cloud Community profile data.
package googlecloud

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

const platform = "googlecloud"

// platformInfo implements profile.Platform for Google Cloud Community.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() {
	profile.RegisterWithFetcher(platformInfo{}, fetchProfile)
}

// fetchProfile is the FetchFunc for Google Cloud Community profiles.
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

var (
	// Match cloud.google.com/community patterns
	usernamePattern1 = regexp.MustCompile(`(?i)cloud\.google\.com/community/users?/([a-zA-Z0-9_-]+)`)
	// Match gcp.community patterns
	usernamePattern2 = regexp.MustCompile(`(?i)gcp\.community/u/([a-zA-Z0-9_-]+)`)
)

// Match returns true if the URL is a Google Cloud Community profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return (strings.Contains(lower, "cloud.google.com/community") && usernamePattern1.MatchString(urlStr)) ||
		(strings.Contains(lower, "gcp.community") && usernamePattern2.MatchString(urlStr))
}

// AuthRequired returns false because Google Cloud Community profiles are generally public.
func AuthRequired() bool { return false }

// Client handles Google Cloud Community requests.
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

// New creates a Google Cloud Community client.
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

var (
	postCountPattern  = regexp.MustCompile(`(?i)(\d+(?:,\d+)?)\s*(?:posts?|contributions?)`)
	pointsPattern     = regexp.MustCompile(`(?i)(\d+(?:,\d+)?)\s*(?:points?|reputation)`)
	badgesPattern     = regexp.MustCompile(`(?i)(\d+(?:,\d+)?)\s*(?:badges?)`)
	avatarPattern     = regexp.MustCompile(`<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	gcpAvatarPattern  = regexp.MustCompile(`<img[^>]+alt="[^"]*profile[^"]*"[^>]+src="([^"]+)"`)
)

// Fetch retrieves a Google Cloud Community profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching google cloud community profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	prof := parseHTML(string(body), urlStr, username)

	return prof, nil
}

func parseHTML(html, urlStr, username string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         urlStr,
		Username:    username,
		DisplayName: username,
		Fields:      make(map[string]string),
	}

	// Extract name from title
	if title := htmlutil.Title(html); title != "" {
		name := strings.TrimSuffix(title, " | Google Cloud Community")
		name = strings.TrimSuffix(name, " - Google Cloud")
		name = strings.TrimSpace(name)
		if name != "" {
			p.DisplayName = name
		}
	}

	// Extract bio/description
	p.Bio = htmlutil.Description(html)

	// Extract avatar
	if m := avatarPattern.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = m[1]
	} else if m := gcpAvatarPattern.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	// Extract post count
	if m := postCountPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["post_count"] = strings.ReplaceAll(m[1], ",", "")
	}

	// Extract points/reputation
	if m := pointsPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["points"] = strings.ReplaceAll(m[1], ",", "")
	}

	// Extract badges
	if m := badgesPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["badges"] = strings.ReplaceAll(m[1], ",", "")
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(html)

	return p
}

func extractUsername(urlStr string) string {
	if matches := usernamePattern1.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}
	if matches := usernamePattern2.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}
	return ""
}
