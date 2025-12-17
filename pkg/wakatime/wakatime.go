// Package wakatime fetches WakaTime user profile data.
package wakatime

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

const platform = "wakatime"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)wakatime\.com/@([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a WakaTime profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "wakatime.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because WakaTime profiles are public.
func AuthRequired() bool { return false }

// Client handles WakaTime requests.
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

// New creates a WakaTime client.
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
	displayNameAlt     = regexp.MustCompile(`(?i)<title>@([^<|]+)`)
	avatarPattern      = regexp.MustCompile(`(?i)<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	locationPattern    = regexp.MustCompile(`(?i)<span[^>]*class="[^"]*location[^"]*"[^>]*>([^<]+)</span>`)
	websitePattern     = regexp.MustCompile(`(?i)<a[^>]+href="(https?://[^"]+)"[^>]*class="[^"]*website[^"]*"`)
	joinedPattern      = regexp.MustCompile(`(?i)Member since[^<]*<[^>]*>([^<]+)<`)
	bioPattern         = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*bio[^"]*"[^>]*>([^<]+)</div>`)
	codingTimePattern  = regexp.MustCompile(`(?i)<span[^>]*class="[^"]*coding-time[^"]*"[^>]*>([^<]+)</span>`)
	languagesPattern   = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*languages[^"]*"[^>]*>([^<]+)</div>`)
	twitterPattern     = regexp.MustCompile(`(?i)href="https?://twitter\.com/([^"/]+)"`)
	githubPattern      = regexp.MustCompile(`(?i)href="https?://github\.com/([^"/]+)"`)
	metaDescPattern    = regexp.MustCompile(`(?i)<meta[^>]+name="description"[^>]+content="([^"]+)"`)
)

// Fetch retrieves a WakaTime profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching wakatime profile", "url", urlStr, "username", username)

	profileURL := "https://wakatime.com/@" + username

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
	if strings.Contains(content, "Page not found") || strings.Contains(content, "404") {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(content, username, urlStr), nil
}

func parseProfile(html, username, url string) *profile.Profile {
	prof := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    username,
		DisplayName: username,
		Fields:      make(map[string]string),
	}

	// Extract display name from title
	if m := displayNameAlt.FindStringSubmatch(html); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" {
			prof.DisplayName = name
		}
	}
	if m := displayNamePattern.FindStringSubmatch(html); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" && name != "@"+username {
			prof.DisplayName = name
		}
	}

	// Extract avatar
	if m := avatarPattern.FindStringSubmatch(html); len(m) > 1 {
		prof.AvatarURL = m[1]
	}

	// Extract location
	if m := locationPattern.FindStringSubmatch(html); len(m) > 1 {
		prof.Location = strings.TrimSpace(m[1])
	}

	// Extract website
	if m := websitePattern.FindStringSubmatch(html); len(m) > 1 {
		prof.Website = m[1]
	}

	// Extract bio
	if m := bioPattern.FindStringSubmatch(html); len(m) > 1 {
		prof.Bio = strings.TrimSpace(m[1])
	}

	// Try to extract bio from meta description
	if prof.Bio == "" {
		if m := metaDescPattern.FindStringSubmatch(html); len(m) > 1 {
			desc := strings.TrimSpace(m[1])
			// Only use if it's not a generic description
			if !strings.Contains(desc, "coding metrics") && !strings.Contains(desc, "WakaTime") {
				prof.Bio = desc
			}
		}
	}

	// Extract joined date
	if m := joinedPattern.FindStringSubmatch(html); len(m) > 1 {
		prof.CreatedAt = strings.TrimSpace(m[1])
	}

	// Extract coding time
	if m := codingTimePattern.FindStringSubmatch(html); len(m) > 1 {
		prof.Fields["coding_time"] = strings.TrimSpace(m[1])
	}

	// Extract languages
	if m := languagesPattern.FindStringSubmatch(html); len(m) > 1 {
		prof.Fields["languages"] = strings.TrimSpace(m[1])
	}

	// Extract social links
	if m := twitterPattern.FindStringSubmatch(html); len(m) > 1 {
		prof.SocialLinks = append(prof.SocialLinks, "https://twitter.com/"+m[1])
	}
	if m := githubPattern.FindStringSubmatch(html); len(m) > 1 {
		prof.SocialLinks = append(prof.SocialLinks, "https://github.com/"+m[1])
	}

	return prof
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
