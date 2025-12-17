// Package blogger fetches Blogger profile data.
package blogger

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

const platform = "blogger"

// platformInfo implements profile.Platform for Blogger.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var (
	// blogspotPattern matches username.blogspot.com URLs.
	blogspotPattern = regexp.MustCompile(`(?i)([a-zA-Z0-9_-]+)\.blogspot\.`)
	// profilePattern matches blogger.com/profile/ID URLs.
	profilePattern = regexp.MustCompile(`(?i)blogger\.com/profile/(\d+)`)
)

// Match returns true if the URL is a Blogger blog or profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if strings.Contains(lower, ".blogspot.") {
		// Skip main blogspot.com without subdomain
		if strings.Contains(lower, "://blogspot.") || strings.Contains(lower, "://www.blogspot.") {
			return false
		}
		return blogspotPattern.MatchString(urlStr)
	}
	if strings.Contains(lower, "blogger.com/profile/") {
		return profilePattern.MatchString(urlStr)
	}
	return false
}

// AuthRequired returns false because Blogger profiles are public.
func AuthRequired() bool { return false }

// Client handles Blogger requests.
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

// New creates a Blogger client.
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

// Fetch retrieves a Blogger blog or profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	profileID := extractProfileID(urlStr)

	c.logger.InfoContext(ctx, "fetching blogger profile", "url", urlStr, "username", username, "profile_id", profileID)

	var fetchURL string
	switch {
	case profileID != "":
		fetchURL = "https://www.blogger.com/profile/" + profileID
	case username != "":
		fetchURL = "https://" + username + ".blogspot.com/"
	default:
		fetchURL = urlStr
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpcache.UserAgent)

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(body, fetchURL, username, profileID), nil
}

func parseHTML(data []byte, urlStr, username, profileID string) *profile.Profile {
	content := string(data)

	displayName := username
	if profileID != "" {
		displayName = ""
	}

	prof := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		DisplayName:   displayName,
		Fields:        make(map[string]string),
	}

	if profileID != "" {
		prof.Fields["profile_id"] = profileID
	}

	// Extract title from og:title or page title
	ogTitle := htmlutil.OGTag(content, "og:title")
	if ogTitle != "" && !strings.Contains(strings.ToLower(ogTitle), "blogger") {
		prof.DisplayName = ogTitle
	}

	// Try extracting name from profile page
	// Pattern: <h1 class="profile-name">Name</h1>
	namePattern := regexp.MustCompile(`<h1[^>]*class="[^"]*profile-name[^"]*"[^>]*>([^<]+)</h1>`)
	if m := namePattern.FindStringSubmatch(content); len(m) > 1 {
		prof.DisplayName = strings.TrimSpace(m[1])
	}

	// Extract avatar from profile image
	avatarPattern := regexp.MustCompile(`<img[^>]+class="[^"]*photo[^"]*"[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.AvatarURL = m[1]
	}

	// Try og:image
	if prof.AvatarURL == "" {
		ogImage := htmlutil.OGTag(content, "og:image")
		if ogImage != "" && !strings.Contains(ogImage, "blogspot") {
			prof.AvatarURL = ogImage
		}
	}

	// Extract description from og:description
	ogDesc := htmlutil.OGTag(content, "og:description")
	if ogDesc != "" {
		prof.Bio = ogDesc
	}

	// Extract location from profile page
	// Pattern: <span class="profile-location">Location</span>
	locationPattern := regexp.MustCompile(`<span[^>]*class="[^"]*(?:adr|profile-location)[^"]*"[^>]*>([^<]+)</span>`)
	if m := locationPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Location = strings.TrimSpace(m[1])
	}

	// Extract industry/occupation
	industryPattern := regexp.MustCompile(`<span[^>]*class="[^"]*(?:industry|profile-industry)[^"]*"[^>]*>([^<]+)</span>`)
	if m := industryPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["industry"] = strings.TrimSpace(m[1])
	}

	// Extract "About Me" section
	aboutPattern := regexp.MustCompile(`(?i)(?:about me|intro)[^<]*</[^>]+>\s*<[^>]+>([^<]+)`)
	if m := aboutPattern.FindStringSubmatch(content); len(m) > 1 {
		bio := strings.TrimSpace(m[1])
		if bio != "" && prof.Bio == "" {
			prof.Bio = bio
		}
	}

	// Extract social links (excluding blogger/blogspot links)
	for _, link := range htmlutil.SocialLinks(content) {
		if !strings.Contains(link, "blogspot.") && !strings.Contains(link, "blogger.com") {
			prof.SocialLinks = append(prof.SocialLinks, link)
		}
	}

	return prof
}

func extractUsername(urlStr string) string {
	matches := blogspotPattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func extractProfileID(urlStr string) string {
	matches := profilePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
