// Package kaggle fetches Kaggle profile data.
package kaggle

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "kaggle"

// platformInfo implements profile.Platform for Kaggle.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Kaggle profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "kaggle.com/") {
		return false
	}
	// Extract path after kaggle.com/
	idx := strings.Index(lower, "kaggle.com/")
	path := lower[idx+len("kaggle.com/"):]
	path = strings.TrimSuffix(path, "/")
	if qIdx := strings.Index(path, "?"); qIdx >= 0 {
		path = path[:qIdx]
	}
	// Must be just username (no slashes) for a profile page
	if strings.Contains(path, "/") {
		return false
	}
	// Skip known non-profile paths
	nonProfiles := map[string]bool{
		"competitions": true, "datasets": true, "code": true, "discussions": true,
		"learn": true, "host": true, "about": true, "terms": true,
		"privacy": true, "docs": true, "search": true,
	}
	return path != "" && !nonProfiles[path]
}

// AuthRequired returns false because Kaggle profiles are public.
func AuthRequired() bool { return false }

// Client handles Kaggle requests.
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

// New creates a Kaggle client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a Kaggle profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	// Normalize URL
	urlStr = "https://www.kaggle.com/" + username

	c.logger.InfoContext(ctx, "fetching kaggle profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(body, urlStr, username), nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	prof := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Try to extract embedded JSON data that Kaggle includes for SSR
	// Pattern: window.Kaggle = {...}
	kaggleDataPattern := regexp.MustCompile(`window\.Kaggle\s*=\s*({[^;]+});`)
	if m := kaggleDataPattern.FindStringSubmatch(content); len(m) > 1 {
		parseKaggleJSON(m[1], prof)
	}

	// Extract from og:title meta tag
	ogTitlePattern := regexp.MustCompile(`<meta[^>]+property="og:title"[^>]+content="([^"]+)"`)
	if m := ogTitlePattern.FindStringSubmatch(content); len(m) > 1 {
		title := html.UnescapeString(m[1])
		title, _ = strings.CutSuffix(title, " | Kaggle")
		if title != "" && title != username {
			prof.Name = title
		}
	}

	// Extract avatar from og:image
	ogImagePattern := regexp.MustCompile(`<meta[^>]+property="og:image"[^>]+content="([^"]+)"`)
	if m := ogImagePattern.FindStringSubmatch(content); len(m) > 1 {
		prof.AvatarURL = m[1]
	}

	// Extract description from og:description
	ogDescPattern := regexp.MustCompile(`<meta[^>]+property="og:description"[^>]+content="([^"]+)"`)
	if m := ogDescPattern.FindStringSubmatch(content); len(m) > 1 {
		desc := strings.TrimSpace(html.UnescapeString(m[1]))
		if desc != "" && !strings.Contains(desc, "Kaggle is the world") {
			prof.Bio = desc
		}
	}

	// Extract tier from meta description (often contains tier info)
	tierPattern := regexp.MustCompile(`(Grandmaster|Master|Expert|Contributor|Novice)`)
	if m := tierPattern.FindStringSubmatch(content); len(m) > 1 {
		if prof.Badges == nil {
			prof.Badges = make(map[string]string)
		}
		prof.Badges[m[1]] = "1"
	}

	return prof
}

func parseKaggleJSON(jsonStr string, prof *profile.Profile) {
	var data map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return
	}

	// Try to extract user info from the embedded data
	if user, ok := data["user"].(map[string]any); ok {
		if displayName, ok := user["displayName"].(string); ok && displayName != "" {
			prof.Name = displayName
		}
		if bio, ok := user["bio"].(string); ok && bio != "" {
			prof.Bio = bio
		}
		if avatarURL, ok := user["avatarUrl"].(string); ok && avatarURL != "" {
			prof.AvatarURL = avatarURL
		}
		if tier, ok := user["tier"].(string); ok && tier != "" {
			if prof.Badges == nil {
				prof.Badges = make(map[string]string)
			}
			prof.Badges[tier] = "1"
		}
		if country, ok := user["country"].(string); ok && country != "" {
			prof.Location = country
		}
		if organization, ok := user["organization"].(string); ok && organization != "" {
			prof.Fields["organization"] = organization
		}
	}
}

func extractUsername(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "www.")

	// Extract kaggle.com/username
	re := regexp.MustCompile(`kaggle\.com/([^/?]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
