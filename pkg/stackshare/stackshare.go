// Package stackshare fetches StackShare user profile data.
package stackshare

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

const platform = "stackshare"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)stackshare\.io/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a StackShare profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "stackshare.io") {
		return false
	}
	// Exclude non-profile paths (companies, stacks, etc.)
	excluded := []string{"/stacks/", "/tools/", "/posts/", "/feed"}
	for _, ex := range excluded {
		if strings.Contains(lower, ex) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because StackShare profiles are public.
func AuthRequired() bool { return false }

// Client handles StackShare requests.
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

// New creates a StackShare client.
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
	displayNamePattern = regexp.MustCompile(`(?i)<h1[^>]*class="[^"]*profile-name[^"]*"[^>]*>([^<]+)</h1>`)
	displayNameOG      = regexp.MustCompile(`(?i)<meta[^>]+property="og:title"[^>]+content="([^"]+)"`)
	avatarPattern      = regexp.MustCompile(`(?i)<img[^>]+class="[^"]*profile-avatar[^"]*"[^>]+src="([^"]+)"`)
	avatarOG           = regexp.MustCompile(`(?i)<meta[^>]+property="og:image"[^>]+content="([^"]+)"`)
	bioPattern         = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*profile-bio[^"]*"[^>]*>([^<]+)</div>`)
	bioMeta            = regexp.MustCompile(`(?i)<meta[^>]+name="description"[^>]+content="([^"]+)"`)
	locationPattern    = regexp.MustCompile(`(?i)<span[^>]*class="[^"]*location[^"]*"[^>]*>([^<]+)</span>`)
	companyPattern     = regexp.MustCompile(`(?i)<span[^>]*class="[^"]*company[^"]*"[^>]*>([^<]+)</span>`)
	stacksPattern      = regexp.MustCompile(`(?i)(\d+)\s*stacks?`)
	followersPattern   = regexp.MustCompile(`(?i)(\d+)\s*followers?`)
	twitterPattern     = regexp.MustCompile(`(?i)href="https?://twitter\.com/([^"/]+)"`)
	githubPattern      = regexp.MustCompile(`(?i)href="https?://github\.com/([^"/]+)"`)
	websitePattern     = regexp.MustCompile(`(?i)<a[^>]+href="(https?://[^"]+)"[^>]*class="[^"]*website[^"]*"`)
)

// Fetch retrieves a StackShare profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching stackshare profile", "url", urlStr, "username", username)

	profileURL := "https://stackshare.io/" + username

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

	// Extract display name from og:title
	if m := displayNameOG.FindStringSubmatch(html); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		// Remove " | StackShare" suffix
		if idx := strings.Index(name, " |"); idx > 0 {
			name = strings.TrimSpace(name[:idx])
		}
		if idx := strings.Index(name, " on StackShare"); idx > 0 {
			name = strings.TrimSpace(name[:idx])
		}
		if name != "" && name != username {
			prof.DisplayName = name
		}
	}

	if m := displayNamePattern.FindStringSubmatch(html); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" {
			prof.DisplayName = name
		}
	}

	// Extract avatar from og:image
	if m := avatarOG.FindStringSubmatch(html); len(m) > 1 {
		avatar := m[1]
		if strings.Contains(avatar, "avatar") || strings.Contains(avatar, "profile") {
			prof.AvatarURL = avatar
		}
	}
	if prof.AvatarURL == "" {
		if m := avatarPattern.FindStringSubmatch(html); len(m) > 1 {
			prof.AvatarURL = m[1]
		}
	}

	// Extract location
	if m := locationPattern.FindStringSubmatch(html); len(m) > 1 {
		prof.Location = strings.TrimSpace(m[1])
	}

	// Extract company
	if m := companyPattern.FindStringSubmatch(html); len(m) > 1 {
		company := strings.TrimSpace(m[1])
		if company != "" {
			prof.Groups = append(prof.Groups, company)
			prof.Fields["company"] = company
		}
	}

	// Extract bio from meta description
	if m := bioMeta.FindStringSubmatch(html); len(m) > 1 {
		bio := strings.TrimSpace(m[1])
		if !strings.Contains(bio, "StackShare") && len(bio) > 20 {
			prof.Bio = bio
		}
	}
	if prof.Bio == "" {
		if m := bioPattern.FindStringSubmatch(html); len(m) > 1 {
			prof.Bio = strings.TrimSpace(m[1])
		}
	}

	// Extract stacks count
	if m := stacksPattern.FindStringSubmatch(html); len(m) > 1 {
		prof.Fields["stacks"] = m[1]
	}

	// Extract followers count
	if m := followersPattern.FindStringSubmatch(html); len(m) > 1 {
		prof.Fields["followers"] = m[1]
	}

	// Extract website
	if m := websitePattern.FindStringSubmatch(html); len(m) > 1 {
		prof.Website = m[1]
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
		username := matches[1]
		// Remove trailing path
		if idx := strings.Index(username, "/"); idx > 0 {
			username = username[:idx]
		}
		return username
	}
	return ""
}
