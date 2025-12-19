// Package ithelp fetches iT邦幫忙 (IT Help) user profile data.
package ithelp

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

const platform = "ithelp"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)ithelp\.ithome\.com\.tw/users/(\d+)`)

// Match returns true if the URL is an iT邦幫忙 profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "ithelp.ithome.com.tw") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because iT邦幫忙 profiles are public.
func AuthRequired() bool { return false }

// Client handles iT邦幫忙 requests.
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

// New creates an iT邦幫忙 client.
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
	displayNamePattern = regexp.MustCompile(`(?i)<h2[^>]*class="[^"]*profile-name[^"]*"[^>]*>([^<]+)</h2>`)
	bioPattern         = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*profile-intro[^"]*"[^>]*>([^<]+)</div>`)
	avatarPattern      = regexp.MustCompile(`(?i)<img[^>]+class="[^"]*profile-user__img[^"]*"[^>]+src="([^"]+)"`)
	articleCountPat    = regexp.MustCompile(`(?i)文章\s*<span[^>]*>(\d+)</span>`)
	qaCountPattern     = regexp.MustCompile(`(?i)問答\s*<span[^>]*>(\d+)</span>`)
	ironmanPattern     = regexp.MustCompile(`(?i)參賽次數\s*<span[^>]*>(\d+)</span>`)
)

// Fetch retrieves an iT邦幫忙 profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	userID := extractUserID(urlStr)
	if userID == "" {
		return nil, fmt.Errorf("could not extract user ID from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching ithelp profile", "url", urlStr, "user_id", userID)

	profileURL := "https://ithelp.ithome.com.tw/users/" + userID + "/profile"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	// Enhanced anti-bot headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Referer", "https://ithelp.ithome.com.tw/")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	content := string(body)

	// Check if profile exists
	if strings.Contains(content, "not found") || strings.Contains(content, "找不到") {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(content, userID, urlStr), nil
}

func parseProfile(htmlContent, userID, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    userID,
		DisplayName: userID,
		Fields:      make(map[string]string),
	}

	// Extract display name
	if m := displayNamePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		name := strings.TrimSpace(html.UnescapeString(m[1]))
		if name != "" {
			p.DisplayName = name
		}
	}

	// Extract bio/introduction
	if m := bioPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		bioText := strings.TrimSpace(html.UnescapeString(m[1]))
		if bioText != "" {
			p.Bio = bioText
		}
	}

	// Extract avatar
	if m := avatarPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		avatarURL := m[1]
		if !strings.Contains(avatarURL, "default") {
			// Make absolute URL if needed
			if strings.HasPrefix(avatarURL, "//") {
				avatarURL = "https:" + avatarURL
			} else if strings.HasPrefix(avatarURL, "/") {
				avatarURL = "https://ithelp.ithome.com.tw" + avatarURL
			}
			p.AvatarURL = avatarURL
		}
	}

	// Extract article count
	if m := articleCountPat.FindStringSubmatch(htmlContent); len(m) > 1 {
		p.Fields["articles"] = m[1]
	}

	// Extract Q&A count
	if m := qaCountPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		p.Fields["qa_count"] = m[1]
	}

	// Extract Ironman competition participation count
	if m := ironmanPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		p.Fields["ironman_participations"] = m[1]
	}

	// Extract social media links
	socialLinks := htmlutil.SocialLinks(htmlContent)
	if len(socialLinks) > 0 {
		p.SocialLinks = socialLinks
	}

	return p
}

func extractUserID(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
