// Package codechef fetches CodeChef user profile data.
package codechef

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

const platform = "codechef"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)codechef\.com/users/([a-zA-Z0-9_]+)`)

// Match returns true if the URL is a CodeChef profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "codechef.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because CodeChef profiles are public.
func AuthRequired() bool { return false }

// Client handles CodeChef requests.
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

// New creates a CodeChef client.
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
	displayNamePattern = regexp.MustCompile(`(?i)<h1[^>]*class="h2-style"[^>]*>([^<]+)</h1>`)
	ratingPattern      = regexp.MustCompile(`(?i)<div[^>]*class="rating-number"[^>]*>(\d+)</div>`)
	starsPattern       = regexp.MustCompile(`(?i)<span[^>]*class="rating"[^>]*>([^<]+)</span>`)
	countryPattern     = regexp.MustCompile(`(?i)<span[^>]*class="user-country-name"[^>]*>([^<]+)</span>`)
	avatarPattern      = regexp.MustCompile(`(?i)<img[^>]+class="profileImage"[^>]+src="([^"]+)"`)
	institutionPattern = regexp.MustCompile(`(?i)<span[^>]*>([^<]*University[^<]*|[^<]*Institute[^<]*|[^<]*College[^<]*)</span>`)
	globalRankPattern  = regexp.MustCompile(`(?i)Global Rank[^<]*<[^>]*>[^<]*<strong>(\d+)</strong>`)
	countryRankPattern = regexp.MustCompile(`(?i)Country Rank[^<]*<[^>]*>[^<]*<strong>(\d+)</strong>`)
)

// Fetch retrieves a CodeChef profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching codechef profile", "url", urlStr, "username", username)

	profileURL := "https://www.codechef.com/users/" + username

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
	if strings.Contains(content, "User not found") || strings.Contains(content, "page not found") {
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

	// Extract display name
	if m := displayNamePattern.FindStringSubmatch(html); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" && name != username {
			p.DisplayName = name
		}
	}

	// Extract avatar
	if m := avatarPattern.FindStringSubmatch(html); len(m) > 1 {
		avatarURL := m[1]
		if !strings.Contains(avatarURL, "default") {
			p.AvatarURL = avatarURL
		}
	}

	// Extract country
	if m := countryPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract rating
	if m := ratingPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["rating"] = m[1]
	}

	// Extract star rating
	if m := starsPattern.FindStringSubmatch(html); len(m) > 1 {
		stars := strings.TrimSpace(m[1])
		if stars != "" {
			p.Fields["stars"] = stars
		}
	}

	// Extract institution
	if m := institutionPattern.FindStringSubmatch(html); len(m) > 1 {
		inst := strings.TrimSpace(m[1])
		if inst != "" {
			p.Groups = append(p.Groups, inst)
			p.Fields["institution"] = inst
		}
	}

	// Extract global rank
	if m := globalRankPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["global_rank"] = m[1]
	}

	// Extract country rank
	if m := countryRankPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["country_rank"] = m[1]
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
