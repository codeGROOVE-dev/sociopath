// Package devrant fetches devRant user profile data.
package devrant

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

const platform = "devrant"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)devrant\.com/users/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a devRant profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "devrant.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because devRant profiles are public.
func AuthRequired() bool { return false }

// Client handles devRant requests.
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

// New creates a devRant client.
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
	displayNamePattern = regexp.MustCompile(`(?i)<h1[^>]*class="[^"]*username[^"]*"[^>]*>([^<]+)</h1>`)
	avatarPattern      = regexp.MustCompile(`(?i)<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	avatarAlt          = regexp.MustCompile(`(?i)<img[^>]+src="(https://avatars\.devrant\.com[^"]+)"`)
	scorePattern       = regexp.MustCompile(`(?i)(\d+)\s*\+\+`)
	locationPattern    = regexp.MustCompile(`(?i)<span[^>]*class="[^"]*location[^"]*"[^>]*>([^<]+)</span>`)
	bioPattern         = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*about[^"]*"[^>]*>([^<]+)</div>`)
	skillsPattern      = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*skills[^"]*"[^>]*>([^<]+)</div>`)
	rantsPattern       = regexp.MustCompile(`(?i)(\d+)\s*rants?`)
	githubPattern      = regexp.MustCompile(`(?i)href="https?://github\.com/([^"/]+)"`)
	websitePattern     = regexp.MustCompile(`(?i)<a[^>]+href="(https?://[^"]+)"[^>]*class="[^"]*website[^"]*"`)
)

// Fetch retrieves a devRant profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching devrant profile", "url", urlStr, "username", username)

	profileURL := "https://devrant.com/users/" + username

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
	if strings.Contains(content, "User not found") || strings.Contains(content, "404") {
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
		if name != "" {
			p.DisplayName = name
		}
	}

	// Extract avatar
	if m := avatarAlt.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = m[1]
	} else if m := avatarPattern.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	// Extract location
	if m := locationPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract bio/about
	if m := bioPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Bio = strings.TrimSpace(m[1])
	}

	// Extract skills
	if m := skillsPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["skills"] = strings.TrimSpace(m[1])
	}

	// Extract score (++)
	if m := scorePattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["score"] = m[1]
	}

	// Extract rants count
	if m := rantsPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["rants"] = m[1]
	}

	// Extract website
	if m := websitePattern.FindStringSubmatch(html); len(m) > 1 {
		p.Website = m[1]
	}

	// Extract GitHub link
	if m := githubPattern.FindStringSubmatch(html); len(m) > 1 {
		p.SocialLinks = append(p.SocialLinks, "https://github.com/"+m[1])
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
