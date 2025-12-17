// Package atcoder fetches AtCoder user profile data.
package atcoder

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "atcoder"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)atcoder\.jp/users/([a-zA-Z0-9_]+)`)

// Match returns true if the URL is an AtCoder profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "atcoder.jp") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because AtCoder profiles are public.
func AuthRequired() bool { return false }

// Client handles AtCoder requests.
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

// New creates an AtCoder client.
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

var (
	ratingPattern      = regexp.MustCompile(`(?i)<th[^>]*>Rating</th>\s*<td[^>]*><span[^>]*>(\d+)</span>`)
	highestPattern     = regexp.MustCompile(`(?i)<th[^>]*>Highest Rating</th>\s*<td[^>]*><span[^>]*>(\d+)</span>`)
	rankPattern        = regexp.MustCompile(`(?i)<th[^>]*>Rank</th>\s*<td[^>]*>(\d+)\D`)
	countryPattern     = regexp.MustCompile(`(?i)<img[^>]+flag-([a-z]{2})[^>]*>`)
	affiliationPattern = regexp.MustCompile(`(?i)<th[^>]*>Affiliation</th>\s*<td[^>]*>([^<]+)</td>`)
	birthdayPattern    = regexp.MustCompile(`(?i)<th[^>]*>Birth Year</th>\s*<td[^>]*>(\d+)</td>`)
	avatarPattern      = regexp.MustCompile(`(?i)<img[^>]+class="avatar"[^>]+src="([^"]+)"`)
	twitterPattern     = regexp.MustCompile(`(?i)href="https?://twitter\.com/([^"/]+)"`)
	userScreenNamePat  = regexp.MustCompile(`(?i)<a[^>]+class="username"[^>]*><span[^>]*>([^<]+)</span></a>`)
)

// Fetch retrieves an AtCoder profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching atcoder profile", "url", urlStr, "username", username)

	profileURL := "https://atcoder.jp/users/" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	content := string(body)

	// Check if profile exists
	if strings.Contains(content, "404 Not Found") || strings.Contains(content, "Page not found") {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(content, username, urlStr), nil
}

func parseProfile(html, username, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    username,
		DisplayName: username,
		Fields:      make(map[string]string),
	}

	// Extract display name (user screen name from span)
	if m := userScreenNamePat.FindStringSubmatch(html); len(m) > 1 {
		p.DisplayName = strings.TrimSpace(m[1])
	}

	// Extract avatar
	if m := avatarPattern.FindStringSubmatch(html); len(m) > 1 {
		avatarURL := m[1]
		if !strings.HasPrefix(avatarURL, "http") {
			avatarURL = "https://atcoder.jp" + avatarURL
		}
		if !strings.Contains(avatarURL, "icon_default_user") {
			p.AvatarURL = avatarURL
		}
	}

	// Extract country from flag
	if m := countryPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Location = strings.ToUpper(m[1])
	}

	// Extract affiliation
	if m := affiliationPattern.FindStringSubmatch(html); len(m) > 1 {
		affiliation := strings.TrimSpace(m[1])
		if affiliation != "" {
			p.Groups = append(p.Groups, affiliation)
			p.Fields["affiliation"] = affiliation
		}
	}

	// Extract rating
	if m := ratingPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["rating"] = m[1]
	}

	// Extract highest rating
	if m := highestPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["highest_rating"] = m[1]
	}

	// Extract rank
	if m := rankPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["rank"] = m[1]
	}

	// Extract birth year
	if m := birthdayPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["birth_year"] = m[1]
	}

	// Extract Twitter handle as social link
	if m := twitterPattern.FindStringSubmatch(html); len(m) > 1 {
		p.SocialLinks = append(p.SocialLinks, "https://twitter.com/"+m[1])
	}

	return p
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
