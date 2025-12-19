// Package codingame fetches CodinGame profile data.
// CodinGame is a coding challenge and game platform for developers.
// Note: CodinGame uses an undocumented API and heavily relies on JavaScript,
// so profile data extraction may be limited without API access.
package codingame

import (
	"context"
	"crypto/tls"
	"encoding/json"
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

const platform = "codingame"

// platformInfo implements profile.Platform for CodinGame.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a CodinGame profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "codingame.com/") {
		return false
	}
	// Profile URLs are codingame.com/profile/handle or codingame.com/profile/username
	return strings.Contains(lower, "/profile/")
}

// AuthRequired returns false because CodinGame profiles are public (but may need API).
func AuthRequired() bool { return false }

// Client handles CodinGame requests.
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

// New creates a CodinGame client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves a CodinGame profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	handle := extractHandle(urlStr)
	if handle == "" {
		return nil, fmt.Errorf("could not extract handle/username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching codingame profile", "url", urlStr, "handle", handle)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, urlStr, handle)
}

// parseProfile extracts profile data from CodinGame HTML/JSON.
func parseProfile(data []byte, urlStr, handle string) (*profile.Profile, error) {
	content := string(data)

	// Check if profile exists
	if htmlutil.IsNotFound(content) {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      handle,
		Fields:        make(map[string]string),
	}

	// CodinGame embeds data in JavaScript variables
	// Try to extract from window.__NUXT__ or similar
	nuxtRe := regexp.MustCompile(`window\.__NUXT__\s*=\s*(\{.+?\});`)
	if m := nuxtRe.FindStringSubmatch(content); len(m) > 1 {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(m[1]), &data); err == nil {
			extractFromNuxtData(p, data)
		}
	}

	// Try to extract from meta tags
	extractFromMetaTags(p, content)

	// If no display name found, it might be a generic page
	if p.DisplayName == "" {
		return nil, profile.ErrProfileNotFound
	}

	// Extract display name from title if still empty
	if p.DisplayName == "" {
		titleRe := regexp.MustCompile(`<title>([^<\-|]+)`)
		if m := titleRe.FindStringSubmatch(content); len(m) > 1 {
			name := strings.TrimSpace(m[1])
			if !strings.Contains(name, "CodinGame") {
				p.DisplayName = name
			}
		}
	}

	// Final check: if it still looks generic, it's not a profile
	if p.DisplayName == "" || htmlutil.IsGenericTitle(p.DisplayName) {
		return nil, profile.ErrProfileNotFound
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	return p, nil
}

// extractFromNuxtData extracts profile data from Nuxt.js data structure.
func extractFromNuxtData(prof *profile.Profile, data map[string]interface{}) {
	// Navigate through nested structure to find user data
	// This is a best-effort extraction based on common patterns
	if state, ok := data["state"].(map[string]interface{}); ok {
		if user, ok := state["user"].(map[string]interface{}); ok {
			if pseudo, ok := user["pseudo"].(string); ok && pseudo != "" {
				prof.DisplayName = pseudo
			}
			if publicHandle, ok := user["publicHandle"].(string); ok && publicHandle != "" {
				prof.Fields["public_handle"] = publicHandle
			}
			if avatar, ok := user["avatar"].(string); ok && avatar != "" {
				if !strings.HasPrefix(avatar, "http") {
					avatar = "https://www.codingame.com" + avatar
				}
				prof.AvatarURL = avatar
			}
			if country, ok := user["country"].(string); ok && country != "" {
				prof.Location = country
			}
			if company, ok := user["company"].(string); ok && company != "" {
				prof.Fields["company"] = company
			}
			if rank, ok := user["rank"].(float64); ok {
				prof.Fields["rank"] = fmt.Sprintf("%.0f", rank)
			}
			if level, ok := user["level"].(float64); ok {
				prof.Fields["level"] = fmt.Sprintf("%.0f", level)
			}
			if bio, ok := user["biography"].(string); ok && bio != "" {
				prof.Bio = bio
			}
		}
	}
}

// extractFromMetaTags extracts profile data from HTML meta tags.
func extractFromMetaTags(prof *profile.Profile, content string) {
	// Extract from og:title
	titleRe := regexp.MustCompile(`<meta[^>]+property="og:title"[^>]+content="([^"]+)"`)
	if m := titleRe.FindStringSubmatch(content); len(m) > 1 {
		if prof.DisplayName == "" {
			prof.DisplayName = strings.TrimSpace(m[1])
		}
	}

	// Extract from og:description
	descRe := regexp.MustCompile(`<meta[^>]+property="og:description"[^>]+content="([^"]+)"`)
	if m := descRe.FindStringSubmatch(content); len(m) > 1 {
		desc := strings.TrimSpace(m[1])
		if !strings.Contains(desc, "CodinGame") && prof.Bio == "" {
			prof.Bio = desc
		}
	}

	// Extract from og:image (avatar)
	imageRe := regexp.MustCompile(`<meta[^>]+property="og:image"[^>]+content="([^"]+)"`)
	if m := imageRe.FindStringSubmatch(content); len(m) > 1 {
		if prof.AvatarURL == "" {
			prof.AvatarURL = m[1]
		}
	}
}

// extractHandle extracts public handle or username from CodinGame URL.
func extractHandle(urlStr string) string {
	// Handle codingame.com/profile/handle
	if idx := strings.Index(urlStr, "/profile/"); idx != -1 {
		handle := urlStr[idx+len("/profile/"):]
		handle = strings.Split(handle, "/")[0]
		handle = strings.Split(handle, "?")[0]
		return strings.TrimSpace(handle)
	}
	return ""
}
