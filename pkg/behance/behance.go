// Package behance fetches Behance user profile data.
package behance

import (
	"context"
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

const platform = "behance"

// platformInfo implements profile.Platform for Behance.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)behance\.net/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Behance profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "behance.net/") {
		return false
	}
	// Exclude non-profile paths
	excludePaths := []string{"/search/", "/galleries/", "/joblist/", "/live/", "/discover/", "/awards/", "/project/", "/collection/"}
	for _, p := range excludePaths {
		if strings.Contains(lower, p) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Behance profiles are public.
func AuthRequired() bool { return false }

// Client handles Behance requests.
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

// New creates a Behance client.
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

// Fetch retrieves a Behance profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching behance profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://www.behance.net/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return c.parseProfile(ctx, string(body), profileURL, username)
}

func (c *Client) parseProfile(_ context.Context, html, profileURL, username string) (*profile.Profile, error) {
	p := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Try to extract from JSON-LD (often contains most reliable data)
	if ld := htmlutil.ExtractJSONLD(html); ld != "" {
		// Behance uses schema.org Person or ProfilePage
		if name := extractFromJSONLD(ld, "name"); name != "" && !htmlutil.IsGenericTitle(name) {
			p.DisplayName = name
		}
		if image := extractFromJSONLD(ld, "image"); image != "" && !strings.Contains(image, "default") {
			p.AvatarURL = image
		}
		if loc := extractFromJSONLD(ld, "addressLocality"); loc != "" {
			p.Location = loc
		}
	}

	// Extract display name from title or og:title if still empty
	if p.DisplayName == "" {
		if title := htmlutil.Title(html); title != "" {
			if !htmlutil.IsGenericTitle(title) {
				title = strings.Split(title, " on Behance")[0]
				title = strings.Split(title, " | Behance")[0]
				title = strings.TrimSpace(title)
				if title != "" && title != username && !htmlutil.IsGenericTitle(title) {
					p.DisplayName = title
				}
			}
		}
	}

	if p.DisplayName == "" {
		if ogTitle := htmlutil.OGTitle(html); ogTitle != "" {
			if !htmlutil.IsGenericTitle(ogTitle) {
				ogTitle = strings.Split(ogTitle, " on Behance")[0]
				ogTitle = strings.Split(ogTitle, " | Behance")[0]
				p.DisplayName = strings.TrimSpace(ogTitle)
			}
		}
	}

	if p.DisplayName == "" {
		if twitterTitle := htmlutil.ExtractMetaTag(html, "twitter:title"); twitterTitle != "" {
			if !htmlutil.IsGenericTitle(twitterTitle) {
				twitterTitle = strings.Split(twitterTitle, " on Behance")[0]
				twitterTitle = strings.Split(twitterTitle, " | Behance")[0]
				p.DisplayName = strings.TrimSpace(twitterTitle)
			}
		}
	}

	// Extract avatar - prioritize Adobe PPS service URLs
	if p.AvatarURL == "" {
		avatarPatterns := []*regexp.Regexp{
			regexp.MustCompile(`https://pps\.services\.adobe\.com/api/profile/[^"'\s<>]+`),
			regexp.MustCompile(`https://a5\.behance\.net/[^"'\s<>]+/img/profile/[^"'\s<>]+`),
			regexp.MustCompile(`(?i)<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']`),
			regexp.MustCompile(`(?i)<meta[^>]+name=["']twitter:image["'][^>]+content=["']([^"']+)["']`),
		}
		for _, pattern := range avatarPatterns {
			if matches := pattern.FindStringSubmatch(html); len(matches) > 0 {
				avatarURL := matches[0]
				if len(matches) > 1 {
					avatarURL = matches[1]
				}
				if !strings.Contains(avatarURL, "default") {
					p.AvatarURL = avatarURL
					break
				}
			}
		}
	}

	// Extract bio from description meta tag
	if desc := htmlutil.Description(html); desc != "" {
		if !htmlutil.IsGenericBio(desc) {
			p.Bio = desc
		}
	}

	// Try to extract location from HTML
	if p.Location == "" {
		locationPatterns := []*regexp.Regexp{
			regexp.MustCompile(`(?i)"location"\s*:\s*"([^"]+)"`),
			regexp.MustCompile(`(?i)<span[^>]*class="[^"]*location[^"]*"[^>]*>([^<]+)</span>`),
			regexp.MustCompile(`(?i)class="[^"]*UserInfo-location[^"]*"[^>]*>([^<]+)</span>`),
		}
		for _, pattern := range locationPatterns {
			if matches := pattern.FindStringSubmatch(html); len(matches) > 1 {
				location := strings.TrimSpace(htmlutil.StripTags(matches[1]))
				if location != "" && !strings.Contains(strings.ToLower(location), "location") && len(location) < 100 {
					p.Location = location
					break
				}
			}
		}
	}

	// Final check: if it's a guess and we found nothing unique, reject it
	if (p.DisplayName == "" || htmlutil.IsGenericTitle(p.DisplayName)) && p.AvatarURL == "" && p.Location == "" {
		return nil, profile.ErrProfileNotFound
	}

	// Extract employer/company
	companyPattern := regexp.MustCompile(`(?i)class="[^"]*employer[^"]*"[^>]*>([^<]+)</span>`)
	if matches := companyPattern.FindStringSubmatch(html); len(matches) > 1 {
		company := strings.TrimSpace(htmlutil.StripTags(matches[1]))
		if company != "" {
			p.Fields["employer"] = company
		}
	}

	// Extract social links
	p.SocialLinks = htmlutil.RelMeLinks(html)
	if len(p.SocialLinks) == 0 {
		p.SocialLinks = htmlutil.SocialLinks(html)
	}

	// Try to extract follower/following counts
	followersPattern := regexp.MustCompile(`(?i)([\d,]+)\s+(?:followers?|fans?)`)
	if matches := followersPattern.FindStringSubmatch(html); len(matches) > 1 {
		followers := strings.ReplaceAll(matches[1], ",", "")
		p.Fields["followers"] = followers
	}

	followingPattern := regexp.MustCompile(`(?i)([\d,]+)\s+following`)
	if matches := followingPattern.FindStringSubmatch(html); len(matches) > 1 {
		following := strings.ReplaceAll(matches[1], ",", "")
		p.Fields["following"] = following
	}

	// Extract project count
	projectsPattern := regexp.MustCompile(`(?i)([\d,]+)\s+(?:projects?|works?)`)
	if matches := projectsPattern.FindStringSubmatch(html); len(matches) > 1 {
		projects := strings.ReplaceAll(matches[1], ",", "")
		p.Fields["projects"] = projects
	}

	return p, nil
}

func extractFromJSONLD(ld, key string) string {
	pattern := regexp.MustCompile(`(?i)"` + regexp.QuoteMeta(key) + `"\s*:\s*"([^"]+)"`)
	if matches := pattern.FindStringSubmatch(ld); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
