// Package exercism fetches Exercism profile data.
package exercism

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

const platform = "exercism"

// platformInfo implements profile.Platform for Exercism.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is an Exercism profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "exercism.org/profiles/") && !strings.Contains(lower, "exercism.io/profiles/") {
		return false
	}
	// Extract username path
	var path string
	if idx := strings.Index(lower, "exercism.org/profiles/"); idx >= 0 {
		path = lower[idx+len("exercism.org/profiles/"):]
	} else if idx := strings.Index(lower, "exercism.io/profiles/"); idx >= 0 {
		path = lower[idx+len("exercism.io/profiles/"):]
	}
	path = strings.TrimSuffix(path, "/")
	if qIdx := strings.Index(path, "?"); qIdx >= 0 {
		path = path[:qIdx]
	}
	// Must be just username (no slashes)
	if strings.Contains(path, "/") {
		return false
	}
	return path != ""
}

// AuthRequired returns false because Exercism profiles are public.
func AuthRequired() bool { return false }

// Client handles Exercism requests.
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

// New creates an Exercism client.
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

// Fetch retrieves an Exercism profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	// Normalize URL (use exercism.org)
	urlStr = "https://exercism.org/profiles/" + username

	c.logger.InfoContext(ctx, "fetching exercism profile", "url", urlStr, "username", username)

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

	// Extract name from title or profile header
	// Pattern: <title>iHiD's profile on Exercism</title> or similar
	titlePattern := regexp.MustCompile(`<title>([^']+)'s profile`)
	if m := titlePattern.FindStringSubmatch(content); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != username {
			prof.DisplayName = html.UnescapeString(name)
		}
	}

	// Extract full name from og:title
	ogTitlePattern := regexp.MustCompile(`<meta[^>]+property="og:title"[^>]+content="([^"]+)"`)
	if m := ogTitlePattern.FindStringSubmatch(content); len(m) > 1 {
		title := m[1]
		if strings.Contains(title, "'s profile") {
			name := strings.Split(title, "'s profile")[0]
			if name != username && name != "" {
				prof.DisplayName = html.UnescapeString(name)
			}
		}
	}

	// Extract avatar URL
	avatarPattern := regexp.MustCompile(`<meta[^>]+property="og:image"[^>]+content="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.AvatarURL = m[1]
	}

	// Extract reputation
	reputationPattern := regexp.MustCompile(`(\d{1,3}(?:,\d{3})*)\s*reputation`)
	if m := reputationPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["reputation"] = strings.ReplaceAll(m[1], ",", "")
	}

	// Extract join date - "Member since July 2013"
	joinedPattern := regexp.MustCompile(`Member since\s+(\w+\s+\d{4})`)
	if m := joinedPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["joined"] = m[1]
	}

	// Extract badges count
	badgesPattern := regexp.MustCompile(`(\d+)\s+badges?`)
	if m := badgesPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["badges"] = m[1]
	}

	// Extract bio/description from og:description
	ogDescPattern := regexp.MustCompile(`<meta[^>]+property="og:description"[^>]+content="([^"]+)"`)
	if m := ogDescPattern.FindStringSubmatch(content); len(m) > 1 {
		desc := strings.TrimSpace(html.UnescapeString(m[1]))
		if desc != "" && !strings.Contains(desc, "Exercism is a free") {
			prof.Bio = desc
		}
	}

	return prof
}

func extractUsername(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "www.")

	// Extract exercism.org/profiles/username or exercism.io/profiles/username
	re := regexp.MustCompile(`exercism\.(?:org|io)/profiles/([^/?]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
