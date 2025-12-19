// Package mstechcommunity fetches Microsoft TechCommunity profile data.
package mstechcommunity

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

const platform = "mstechcommunity"

// platformInfo implements profile.Platform for Microsoft TechCommunity.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() {
	profile.RegisterWithFetcher(platformInfo{}, fetchProfile)
}

// fetchProfile is the FetchFunc for Microsoft TechCommunity profiles.
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

var usernamePattern = regexp.MustCompile(`(?i)techcommunity\.microsoft\.com/(?:users/|t5/user/viewprofilepage/user-id/)([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Microsoft TechCommunity profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "techcommunity.microsoft.com") &&
		(strings.Contains(lower, "/users/") || strings.Contains(lower, "/user/viewprofilepage/")) &&
		usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because TechCommunity profiles are public.
func AuthRequired() bool { return false }

// Client handles Microsoft TechCommunity requests.
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

// New creates a Microsoft TechCommunity client.
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
	postCountPattern = regexp.MustCompile(`(?i)(\d+(?:,\d+)?)\s*(?:posts?|messages?)`)
	solutionsPattern = regexp.MustCompile(`(?i)(\d+(?:,\d+)?)\s*(?:solutions?|accepted)`)
	kudosPattern     = regexp.MustCompile(`(?i)(\d+(?:,\d+)?)\s*(?:kudos?|likes?)`)
	avatarPattern    = regexp.MustCompile(`<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
)

// Fetch retrieves a Microsoft TechCommunity profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	userID := extractUserID(urlStr)
	if userID == "" {
		return nil, fmt.Errorf("could not extract user ID from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching microsoft techcommunity profile", "url", urlStr, "user_id", userID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	prof := parseHTML(string(body), urlStr, userID)

	return prof, nil
}

func parseHTML(html, urlStr, userID string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         urlStr,
		Username:    userID,
		DisplayName: userID,
		Fields:      make(map[string]string),
	}

	// Extract name from title
	if title := htmlutil.Title(html); title != "" {
		name := strings.TrimSuffix(title, " - Microsoft Community Hub")
		name = strings.TrimSuffix(name, " - Microsoft Tech Community")
		name = strings.TrimSpace(name)
		if name != "" && !strings.Contains(strings.ToLower(name), "sign in") {
			p.DisplayName = name
		}
	}

	// Extract bio/description
	p.Bio = htmlutil.Description(html)

	// Extract avatar
	if m := avatarPattern.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	// Extract post count
	if m := postCountPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["post_count"] = strings.ReplaceAll(m[1], ",", "")
	}

	// Extract solutions
	if m := solutionsPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["solutions"] = strings.ReplaceAll(m[1], ",", "")
	}

	// Extract kudos
	if m := kudosPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["kudos"] = strings.ReplaceAll(m[1], ",", "")
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(html)

	return p
}

func extractUserID(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
