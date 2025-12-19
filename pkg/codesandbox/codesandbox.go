// Package codesandbox provides CodeSandbox profile detection.
package codesandbox

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

const platform = "codesandbox"

// platformInfo implements profile.Platform for CodeSandbox.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)codesandbox\.io/u/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a CodeSandbox profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "codesandbox.io/u/") {
		return false
	}
	// Exclude non-profile paths
	excludePaths := []string{"/s/", "/sandbox/", "/embed/", "/examples/"}
	for _, p := range excludePaths {
		if strings.Contains(lower, p) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because CodeSandbox profiles are public.
func AuthRequired() bool { return false }

// Client handles CodeSandbox requests.
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

// New creates a CodeSandbox client.
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

// Fetch retrieves a CodeSandbox profile.
// Note: CodeSandbox uses Cloudflare protection, so we can only extract basic info from the URL.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching codesandbox profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	content := string(body)
	if htmlutil.IsNotFound(content) {
		return nil, profile.ErrProfileNotFound
	}

	// CodeSandbox uses Cloudflare protection, but we can still try to extract
	// data if we get a 200 OK.
	p := &profile.Profile{
		Platform: platform,
		URL:      urlStr,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Try to find display name in title
	titleRe := regexp.MustCompile(`(?i)<title>([^<]+)</title>`)
	if m := titleRe.FindStringSubmatch(content); len(m) > 1 {
		title := strings.TrimSpace(m[1])
		if htmlutil.IsGenericTitle(title) {
			return nil, profile.ErrProfileNotFound
		}
		title = strings.Split(title, " - CodeSandbox")[0]
		if title != "" && title != "CodeSandbox" {
			p.DisplayName = title
		}
	}

	// If it's a guess and we found nothing unique, ignore it
	if p.DisplayName == "" {
		return nil, profile.ErrProfileNotFound
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
