// Package sqlru fetches sql.ru forum profile data.
// sql.ru is a Russian database development community forum.
package sqlru

import (
	"context"
	"crypto/tls"
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

const platform = "sqlru"

// platformInfo implements profile.Platform for sql.ru.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a sql.ru profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "sql.ru/") {
		return false
	}
	// Common forum profile patterns: /members/, /member/, /user/, /profile.aspx?id=
	return strings.Contains(lower, "/member") || strings.Contains(lower, "/user") ||
		strings.Contains(lower, "/profile")
}

// AuthRequired returns false because sql.ru profiles are public.
func AuthRequired() bool { return false }

// Client handles sql.ru requests.
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

// New creates a sql.ru client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves a sql.ru profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching sqlru profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, urlStr, username)
}

// parseProfile extracts profile data from sql.ru HTML.
func parseProfile(data []byte, urlStr, username string) (*profile.Profile, error) {
	content := string(data)

	// Check if profile exists
	if strings.Contains(content, "User not found") || strings.Contains(content, "Пользователь не найден") {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Extract display name (common forum patterns)
	nameRe := regexp.MustCompile(`<h1[^>]*>([^<]+)</h1>`)
	if m := nameRe.FindStringSubmatch(content); len(m) > 1 {
		p.DisplayName = strings.TrimSpace(m[1])
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`<img[^>]+(?:class="[^"]*avatar[^"]*"|alt="[^"]*avatar[^"]*")[^>]+src="([^"]+)"`)
	if m := avatarRe.FindStringSubmatch(content); len(m) > 1 {
		avatar := m[1]
		if strings.HasPrefix(avatar, "//") {
			avatar = "https:" + avatar
		} else if !strings.HasPrefix(avatar, "http") && !strings.HasPrefix(avatar, "//") {
			avatar = "https://www.sql.ru" + avatar
		}
		p.AvatarURL = avatar
	}

	// Extract bio/signature
	bioRe := regexp.MustCompile(`(?i)<div[^>]*(?:class="[^"]*signature[^"]*"|class="[^"]*bio[^"]*")[^>]*>([^<]+)</div>`)
	if m := bioRe.FindStringSubmatch(content); len(m) > 1 {
		p.Bio = strings.TrimSpace(m[1])
	}

	// Extract location
	locationRe := regexp.MustCompile(`(?i)(?:Location|Откуда|Расположение)[^:]*:\s*(?:<[^>]+>)?([^<]+)`)
	if m := locationRe.FindStringSubmatch(content); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract post count
	postsRe := regexp.MustCompile(`(?i)(?:Posts|Сообщений)[^:]*:\s*(?:<[^>]+>)?(\d+)`)
	if m := postsRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["posts"] = m[1]
	}

	// Extract registration date
	registeredRe := regexp.MustCompile(`(?i)(?:Registered|Зарегистрирован)[^:]*:\s*(?:<[^>]+>)?([^<]+)`)
	if m := registeredRe.FindStringSubmatch(content); len(m) > 1 {
		p.CreatedAt = strings.TrimSpace(m[1])
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	return p, nil
}

// extractUsername extracts username from sql.ru URL.
func extractUsername(urlStr string) string {
	// Handle various forum profile URL patterns
	patterns := []string{
		"/member/",
		"/members/",
		"/user/",
		"/profile.aspx?id=",
		"/profile?id=",
		"/profile/",
	}

	for _, pattern := range patterns {
		idx := strings.Index(urlStr, pattern)
		if idx == -1 {
			continue
		}
		username := urlStr[idx+len(pattern):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		username = strings.Split(username, "&")[0]
		return strings.TrimSpace(username)
	}

	return ""
}
