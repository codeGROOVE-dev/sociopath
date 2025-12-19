// Package cakeresume fetches CakeResume user profile data.
package cakeresume

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "cakeresume"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)(?:cakeresume\.com|cake\.me)/(?:me/)?([a-zA-Z0-9._-]+)`)

// Match returns true if the URL is a CakeResume profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "cakeresume.com") && !strings.Contains(lower, "cake.me") {
		return false
	}
	// Exclude non-profile paths
	if strings.Contains(lower, "/companies/") ||
		strings.Contains(lower, "/jobs/") ||
		strings.Contains(lower, "/resources/") ||
		strings.Contains(lower, "/portfolios/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because CakeResume profiles can be public.
func AuthRequired() bool { return false }

// Client handles CakeResume requests.
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

// New creates a CakeResume client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

var (
	displayNamePattern = regexp.MustCompile(`(?i)<h1[^>]*class="[^"]*name[^"]*"[^>]*>([^<]+)</h1>`)
	titlePattern       = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*title[^"]*"[^>]*>([^<]+)</div>`)
	locationPattern    = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*location[^"]*"[^>]*>([^<]+)</div>`)
	bioPattern         = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*bio[^"]*"[^>]*>([^<]+)</div>`)
	avatarPattern      = regexp.MustCompile(`(?i)<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	skillPattern       = regexp.MustCompile(`(?i)<span[^>]*class="[^"]*skill[^"]*"[^>]*>([^<]+)</span>`)
)

// Fetch retrieves a CakeResume profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching cakeresume profile", "url", urlStr, "username", username)

	// Try canonical URL format
	profileURL := "https://www.cakeresume.com/" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5,zh-TW;q=0.3")
	req.Header.Set("DNT", "1")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	content := string(body)

	// Check if profile exists
	if strings.Contains(content, "not found") || strings.Contains(content, "404") {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(content, username, urlStr), nil
}

func parseProfile(htmlContent, username, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    username,
		DisplayName: username,
		Fields:      make(map[string]string),
	}

	// Extract display name
	if m := displayNamePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		name := strings.TrimSpace(html.UnescapeString(m[1]))
		if name != "" {
			p.DisplayName = name
		}
	}

	// Extract title/headline
	if m := titlePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		title := strings.TrimSpace(html.UnescapeString(m[1]))
		if title != "" {
			p.Fields["title"] = title
		}
	}

	// Extract location
	if m := locationPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		loc := strings.TrimSpace(html.UnescapeString(m[1]))
		if loc != "" {
			p.Location = loc
		}
	}

	// Extract bio
	if m := bioPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		bioText := strings.TrimSpace(html.UnescapeString(m[1]))
		if bioText != "" {
			p.Bio = bioText
		}
	}

	// Extract avatar
	if m := avatarPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		avatarURL := m[1]
		if !strings.Contains(avatarURL, "default") && !strings.Contains(avatarURL, "placeholder") {
			// Make absolute URL if needed
			if strings.HasPrefix(avatarURL, "//") {
				avatarURL = "https:" + avatarURL
			} else if strings.HasPrefix(avatarURL, "/") {
				avatarURL = "https://www.cakeresume.com" + avatarURL
			}
			p.AvatarURL = avatarURL
		}
	}

	// Extract skills
	matches := skillPattern.FindAllStringSubmatch(htmlContent, -1)
	skills := make([]string, 0)
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 {
			skill := strings.TrimSpace(html.UnescapeString(m[1]))
			if skill != "" && !seen[skill] {
				seen[skill] = true
				skills = append(skills, skill)
			}
		}
	}
	if len(skills) > 0 {
		p.Fields["skills"] = strings.Join(skills, ", ")
	}

	// Extract social media links
	socialLinks := htmlutil.SocialLinks(htmlContent)
	if len(socialLinks) > 0 {
		p.SocialLinks = socialLinks
	}

	// Try to extract website from social links or dedicated field
	for _, link := range socialLinks {
		lower := strings.ToLower(link)
		// If it's not a known social platform, it's likely a personal website
		if !strings.Contains(lower, "github.com") &&
			!strings.Contains(lower, "linkedin.com") &&
			!strings.Contains(lower, "twitter.com") &&
			!strings.Contains(lower, "facebook.com") {
			if p.Website == "" {
				p.Website = link
			}
		}
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
