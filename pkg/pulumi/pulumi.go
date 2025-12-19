// Package pulumi fetches Pulumi (IaC platform) profile data.
package pulumi

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

const platform = "pulumi"

// platformInfo implements profile.Platform for Pulumi.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() {
	profile.RegisterWithFetcher(platformInfo{}, fetchProfile)
}

// fetchProfile is the FetchFunc for Pulumi profiles.
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

var usernamePattern = regexp.MustCompile(`(?i)app\.pulumi\.com/([a-zA-Z0-9_-]+)(?:/|$)`)

// Match returns true if the URL is a Pulumi profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	// Exclude project/stack paths
	if strings.Count(lower, "/") > 4 {
		return false
	}
	return strings.Contains(lower, "app.pulumi.com/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns true because Pulumi profiles may require authentication.
func AuthRequired() bool { return true }

// Client handles Pulumi requests.
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

// New creates a Pulumi client.
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

// Fetch retrieves a Pulumi profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching pulumi profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	if htmlutil.IsNotFound(string(body)) {
		return nil, profile.ErrProfileNotFound
	}

	return parseHTML(body, urlStr, username)
}

func parseHTML(data []byte, urlStr, username string) (*profile.Profile, error) {
	content := string(data)

	p := &profile.Profile{
		Platform: platform,
		URL:      urlStr,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract name from title
	title := htmlutil.Title(content)
	if strings.Contains(title, " | Pulumi") {
		parts := strings.Split(title, " | ")
		if len(parts) > 0 {
			name := strings.TrimSpace(parts[0])
			if name != "" && name != username && !strings.Contains(name, "Pulumi") {
				p.DisplayName = name
			}
		}
	}

	// Extract avatar
	avatarPattern := regexp.MustCompile(`<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(content); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	// If no unique data found, it might be a generic page
	if p.DisplayName == "" && p.AvatarURL == "" && !strings.Contains(content, "Organizations") {
		return nil, profile.ErrProfileNotFound
	}

	if p.DisplayName == "" {
		p.DisplayName = username
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract organizations/projects
	orgPattern := regexp.MustCompile(`<a[^>]+href="https://app\.pulumi\.com/([^/"]+)"[^>]*>([^<]+)</a>`)
	orgMatches := orgPattern.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	for _, m := range orgMatches {
		if len(m) > 1 {
			org := m[1]
			if org != "" && org != username && !seen[org] {
				seen[org] = true
				p.Groups = append(p.Groups, org)
			}
		}
	}

	return p, nil
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
