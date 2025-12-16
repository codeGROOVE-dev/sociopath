// Package sourcehut fetches Sourcehut profile data.
package sourcehut

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "sourcehut"

// platformInfo implements profile.Platform for Sourcehut.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// usernamePattern matches valid Sourcehut usernames (start with ~).
var usernamePattern = regexp.MustCompile(`^~[a-zA-Z0-9_-]+$`)

// Match returns true if the URL is a Sourcehut profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "sr.ht/~") {
		return false
	}
	// Extract path after sr.ht/
	idx := strings.Index(lower, "sr.ht/")
	path := lower[idx+len("sr.ht/"):]
	path = strings.TrimSuffix(path, "/")
	if qIdx := strings.Index(path, "?"); qIdx >= 0 {
		path = path[:qIdx]
	}
	// Must be just ~username (no additional slashes for a profile page)
	if strings.Count(path, "/") > 0 {
		return false
	}
	return usernamePattern.MatchString(path)
}

// AuthRequired returns false because Sourcehut profiles are public.
func AuthRequired() bool { return false }

// Client handles Sourcehut requests.
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

// New creates a Sourcehut client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a Sourcehut profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	// Normalize URL
	if !strings.HasPrefix(urlStr, "http") {
		urlStr = "https://sr.ht/" + username
	}

	c.logger.InfoContext(ctx, "fetching sourcehut profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(body, urlStr, username), nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	prof := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Extract name from title: "~sircmpwn on sourcehut" or similar
	titlePattern := regexp.MustCompile(`<title>([^<]+)</title>`)
	if m := titlePattern.FindStringSubmatch(content); len(m) > 1 {
		title := strings.TrimSpace(m[1])
		// If the title is different from the username, extract the name
		if strings.Contains(title, " on sourcehut") {
			name := strings.TrimSuffix(title, " on sourcehut")
			if name != username {
				prof.DisplayName = html.UnescapeString(name)
			}
		}
	}

	// Extract bio from profile section
	// Pattern: <blockquote class="content">I write code.</blockquote>
	bioPattern := regexp.MustCompile(`<blockquote[^>]*class="[^"]*content[^"]*"[^>]*>([^<]+)</blockquote>`)
	if m := bioPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Bio = strings.TrimSpace(html.UnescapeString(m[1]))
	}
	// Alternative pattern for bio
	if prof.Bio == "" {
		bioPattern2 := regexp.MustCompile(`<div[^>]*class="[^"]*bio[^"]*"[^>]*>([^<]+)</div>`)
		if m := bioPattern2.FindStringSubmatch(content); len(m) > 1 {
			prof.Bio = strings.TrimSpace(html.UnescapeString(m[1]))
		}
	}

	// Extract location
	// Pattern: <span class="icon"><i class="fa fa-globe"></i></span> The Netherlands
	locationPattern := regexp.MustCompile(`<i class="fa fa-globe"></i></span>\s*([^<]+)`)
	if m := locationPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Location = strings.TrimSpace(html.UnescapeString(m[1]))
	}

	// Extract website
	// Pattern: <a href="https://drewdevault.com">https://drewdevault.com</a>
	websitePattern := regexp.MustCompile(`<a[^>]+href="(https?://[^"]+)"[^>]*>https?://[^<]+</a>`)
	if m := websitePattern.FindStringSubmatch(content); len(m) > 1 {
		website := m[1]
		// Filter out sourcehut's own links
		if !strings.Contains(website, "sr.ht") {
			prof.Website = website
		}
	}

	// Extract email if visible
	emailPattern := regexp.MustCompile(`<a[^>]+href="mailto:([^"]+)"`)
	if m := emailPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["email"] = m[1]
	}

	return prof
}

func extractUsername(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "www.")

	// Extract sr.ht/~username
	re := regexp.MustCompile(`sr\.ht/(~[^/?]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
