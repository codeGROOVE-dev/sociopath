// Package launchpad fetches Launchpad user profile data.
package launchpad

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "launchpad"

// platformInfo implements profile.Platform for Launchpad.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)launchpad\.net/~([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Launchpad profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "launchpad.net/~") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Launchpad profiles are public.
func AuthRequired() bool { return false }

// Client handles Launchpad requests.
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

// New creates a Launchpad client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	cache := cfg.cache
	if cache == nil {
		cache = httpcache.NewNull()
	}

	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a Launchpad profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)

	c.logger.InfoContext(ctx, "fetching launchpad profile", "url", urlStr, "username", username)

	profileURL := "https://launchpad.net/~" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpcache.UserAgent)

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(body, profileURL, username), nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	prof := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		DisplayName:   username,
		Fields:        make(map[string]string),
	}

	// Extract display name from title or feed links
	// Pattern: title="Latest Bugs for Liz Fong-Jones"
	namePattern := regexp.MustCompile(`title="Latest \w+ for ([^"]+)"`)
	if m := namePattern.FindStringSubmatch(content); len(m) > 1 {
		prof.DisplayName = strings.TrimSpace(m[1])
	}

	// Extract avatar URL
	// Pattern: <img ... class="logo" src="..." />
	avatarRE := `<a href="[^"]*~` + regexp.QuoteMeta(username) + `"[^>]*>\s*<img[^>]+class="[^"]*logo[^"]*"[^>]+src="([^"]+)"`
	if m := regexp.MustCompile(avatarRE).FindStringSubmatch(content); len(m) > 1 {
		prof.AvatarURL = m[1]
		if strings.HasPrefix(prof.AvatarURL, "/") {
			prof.AvatarURL = "https://launchpad.net" + prof.AvatarURL
		}
	}

	// Fallback: try the API logo URL
	if prof.AvatarURL == "" {
		prof.AvatarURL = "https://launchpad.net/api/devel/~" + username + "/logo"
	}

	// Extract member since date
	// Pattern: <dd id="member-since">2008-05-13</dd>
	memberSincePattern := regexp.MustCompile(`<dd id="member-since">(\d{4}-\d{2}-\d{2})</dd>`)
	if m := memberSincePattern.FindStringSubmatch(content); len(m) > 1 {
		prof.CreatedAt = m[1]
	}

	// Extract timezone - very valuable!
	// Pattern: America/New_York or similar
	timezonePattern := regexp.MustCompile(`(America|Europe|Asia|Africa|Australia|Pacific)/([A-Za-z_]+)`)
	if m := timezonePattern.FindStringSubmatch(content); len(m) > 0 {
		prof.Fields["timezone"] = m[1] + "/" + m[2]
	}

	// Extract karma
	// Pattern: <a id="karma-total" href="...">111</a>
	karmaPattern := regexp.MustCompile(`<a id="karma-total"[^>]*>(\d+)</a>`)
	if m := karmaPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["karma"] = m[1]
	}

	// Extract IRC nickname if present
	ircPattern := regexp.MustCompile(`IRC nickname:\s*</dt>\s*<dd>\s*<span[^>]*>([^<]+)</span>`)
	if m := ircPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["irc"] = strings.TrimSpace(m[1])
	}

	// Extract OpenPGP fingerprint
	pgpPattern := regexp.MustCompile(`([0-9A-F]{4}\s*){10}`)
	if m := pgpPattern.FindString(content); m != "" {
		prof.Fields["pgp_fingerprint"] = strings.ReplaceAll(m, " ", "")
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(content)

	return prof
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
