// Package notist fetches Notist (conference speaker platform) profile data.
package notist

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

const platform = "notist"

// platformInfo implements profile.Platform for Notist.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)noti\.st/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Notist profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	// Exclude presentation paths
	if strings.Contains(lower, "/presentations/") || strings.Contains(lower, "/events/") {
		return false
	}
	return strings.Contains(lower, "noti.st/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Notist profiles are public.
func AuthRequired() bool { return false }

// Client handles Notist requests.
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

// New creates a Notist client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
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

// Fetch retrieves a Notist profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching notist profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	prof := parseHTML(body, urlStr, username)

	return prof, nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	p := &profile.Profile{
		Platform:    platform,
		URL:         urlStr,
		Username:    username,
		DisplayName: username,
		Fields:      make(map[string]string),
	}

	// Extract name from h1 or title
	title := htmlutil.Title(content)
	if strings.Contains(title, " - Notist") {
		parts := strings.Split(title, " - ")
		if len(parts) > 0 {
			p.DisplayName = strings.TrimSpace(parts[0])
		}
	}

	// Extract avatar
	avatarPattern := regexp.MustCompile(`<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(content); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	// Extract bio from meta description or profile bio section
	bioPattern := regexp.MustCompile(`<meta\s+name="description"\s+content="([^"]+)"`)
	if m := bioPattern.FindStringSubmatch(content); len(m) > 1 {
		p.Bio = strings.TrimSpace(m[1])
	}

	// Extract location if available
	locPattern := regexp.MustCompile(`<div[^>]*class="[^"]*location[^"]*"[^>]*>([^<]+)</div>`)
	if m := locPattern.FindStringSubmatch(content); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract website
	websitePattern := regexp.MustCompile(`<a[^>]+class="[^"]*website[^"]*"[^>]+href="([^"]+)"`)
	if m := websitePattern.FindStringSubmatch(content); len(m) > 1 {
		p.Website = m[1]
		if !contains(p.SocialLinks, m[1]) {
			p.SocialLinks = append(p.SocialLinks, m[1])
		}
	}

	// Extract presentations
	presentationPattern := regexp.MustCompile(`<a[^>]+href="(https://noti\.st/[^/]+/[a-zA-Z0-9_-]+)"[^>]*>([^<]+)</a>`)
	presentationMatches := presentationPattern.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	for _, m := range presentationMatches {
		if len(m) > 2 {
			url := m[1]
			title := strings.TrimSpace(m[2])
			if url != "" && !seen[url] && strings.Contains(url, "/presentations/") {
				seen[url] = true
				post := profile.Post{
					Type:  profile.PostTypeEvent,
					Title: title,
					URL:   url,
				}
				p.Posts = append(p.Posts, post)
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

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
