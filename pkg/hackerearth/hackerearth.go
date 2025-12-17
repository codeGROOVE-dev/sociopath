// Package hackerearth fetches HackerEarth user profile data.
package hackerearth

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

const platform = "hackerearth"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)hackerearth\.com/@([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a HackerEarth profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "hackerearth.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because HackerEarth profiles are public.
func AuthRequired() bool { return false }

// Client handles HackerEarth requests.
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

// New creates a HackerEarth client.
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
	displayNameAlt     = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*name[^"]*"[^>]*>([^<]+)</div>`)
	avatarPattern      = regexp.MustCompile(`(?i)<img[^>]+class="[^"]*profile-image[^"]*"[^>]+src="([^"]+)"`)
	avatarAlt          = regexp.MustCompile(`(?i)<img[^>]+src="([^"]+)"[^>]+class="[^"]*avatar[^"]*"`)
	locationPattern    = regexp.MustCompile(`(?i)<span[^>]*class="[^"]*location[^"]*"[^>]*>([^<]+)</span>`)
	companyPattern     = regexp.MustCompile(`(?i)<span[^>]*class="[^"]*company[^"]*"[^>]*>([^<]+)</span>`)
	ratingPattern      = regexp.MustCompile(`(?i)<span[^>]*class="[^"]*rating[^"]*"[^>]*>(\d+)</span>`)
	solvedPattern      = regexp.MustCompile(`(?i)(\d+)\s*problems?\s*solved`)
	titlePattern       = regexp.MustCompile(`(?i)<title>([^<]+)</title>`)
	bioPattern         = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*bio[^"]*"[^>]*>([^<]+)</div>`)
)

// Fetch retrieves a HackerEarth profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching hackerearth profile", "url", urlStr, "username", username)

	profileURL := "https://www.hackerearth.com/@" + username

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
	if strings.Contains(content, "Page not found") || strings.Contains(content, "404") ||
		strings.Contains(content, "User does not exist") {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(content, username, urlStr), nil
}

func parseProfile(html, username, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    username,
		DisplayName: username,
		Fields:      make(map[string]string),
	}

	// Extract display name from title
	if m := titlePattern.FindStringSubmatch(html); len(m) > 1 {
		title := strings.TrimSpace(m[1])
		// Title format: "Name | HackerEarth"
		if idx := strings.Index(title, " |"); idx > 0 {
			name := strings.TrimSpace(title[:idx])
			if name != "" && name != "@"+username {
				p.DisplayName = name
			}
		}
	}

	if m := displayNamePattern.FindStringSubmatch(html); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" {
			p.DisplayName = name
		}
	} else if m := displayNameAlt.FindStringSubmatch(html); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" {
			p.DisplayName = name
		}
	}

	// Extract avatar
	if m := avatarPattern.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = m[1]
	} else if m := avatarAlt.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	// Extract location
	if m := locationPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract company
	if m := companyPattern.FindStringSubmatch(html); len(m) > 1 {
		company := strings.TrimSpace(m[1])
		if company != "" {
			p.Groups = append(p.Groups, company)
			p.Fields["company"] = company
		}
	}

	// Extract bio
	if m := bioPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Bio = strings.TrimSpace(m[1])
	}

	// Extract rating
	if m := ratingPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["rating"] = m[1]
	}

	// Extract problems solved
	if m := solvedPattern.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["problems_solved"] = m[1]
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
