// Package spoj fetches SPOJ (Sphere Online Judge) user profile data.
package spoj

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

const platform = "spoj"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)spoj\.com/users/([a-zA-Z0-9_]+)`)

// Match returns true if the URL is a SPOJ profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "spoj.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because SPOJ profiles are public.
func AuthRequired() bool { return false }

// Client handles SPOJ requests.
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

// New creates a SPOJ client.
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
	displayNamePattern = regexp.MustCompile(`(?i)<h3[^>]*>([^<]+)</h3>`)
	locationPattern    = regexp.MustCompile(`(?i)<dt>Location:</dt>\s*<dd>([^<]+)</dd>`)
	joinedPattern      = regexp.MustCompile(`(?i)<dt>Joined:</dt>\s*<dd>([^<]+)</dd>`)
	worldRankPattern   = regexp.MustCompile(`(?i)<dt>World Rank:</dt>\s*<dd>([^<]+)</dd>`)
	solvedPattern      = regexp.MustCompile(`(?i)<dt>Problems solved:</dt>\s*<dd>(\d+)</dd>`)
	avatarPattern      = regexp.MustCompile(`(?i)<img[^>]+src="([^"]+)"[^>]+class="[^"]*user-avatar[^"]*"`)
	institutionPattern = regexp.MustCompile(`(?i)<dt>Institution:</dt>\s*<dd>([^<]+)</dd>`)
)

// Fetch retrieves a SPOJ profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching spoj profile", "url", urlStr, "username", username)

	profileURL := "https://www.spoj.com/users/" + username + "/"

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
	if strings.Contains(content, "User not found") || strings.Contains(content, "does not exist") {
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
		if !strings.HasPrefix(avatarURL, "http") {
			avatarURL = "https://www.spoj.com" + avatarURL
		}
		if !strings.Contains(avatarURL, "default") && !strings.Contains(avatarURL, "avatar_default") {
			p.AvatarURL = avatarURL
		}
	}

	// Extract location
	if m := locationPattern.FindStringSubmatch(html); len(m) > 1 {
		loc := strings.TrimSpace(m[1])
		if loc != "" {
			p.Location = loc
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

	// Extract joined date
	if m := joinedPattern.FindStringSubmatch(html); len(m) > 1 {
		p.CreatedAt = strings.TrimSpace(m[1])
	}

	// Extract world rank
	if m := worldRankPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["world_rank"] = strings.TrimSpace(m[1])
	}

	// Extract problems solved
	if m := solvedPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["problems_solved"] = m[1]
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
