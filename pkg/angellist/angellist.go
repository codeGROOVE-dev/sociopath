// Package angellist fetches AngelList/Wellfound profile data.
package angellist

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

const platform = "angellist"

// platformInfo implements profile.Platform for AngelList/Wellfound.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)(?:angel\.co|wellfound\.com)/u/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is an AngelList/Wellfound profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return (strings.Contains(lower, "angel.co/u/") ||
		strings.Contains(lower, "wellfound.com/u/")) &&
		usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because AngelList/Wellfound profiles are public.
func AuthRequired() bool { return false }

// Client handles AngelList/Wellfound requests.
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

// New creates an AngelList/Wellfound client.
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

// Fetch retrieves an AngelList/Wellfound profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching angellist profile", "url", urlStr, "username", username)

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

	// Extract name from title or h1
	title := htmlutil.Title(content)
	if strings.Contains(title, " - ") {
		parts := strings.Split(title, " - ")
		if len(parts) > 0 {
			p.DisplayName = strings.TrimSpace(parts[0])
		}
	}

	// Extract avatar
	avatarPattern := regexp.MustCompile(`<img[^>]+(?:class="[^"]*avatar[^"]*"|alt="[^"]*profile[^"]*")[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(content); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	// Extract bio/headline
	bioPattern := regexp.MustCompile(`<meta\s+(?:property="og:description"|name="description")\s+content="([^"]+)"`)
	if m := bioPattern.FindStringSubmatch(content); len(m) > 1 {
		p.Bio = strings.TrimSpace(m[1])
	}

	// Extract location
	locPattern := regexp.MustCompile(`<div[^>]*class="[^"]*location[^"]*"[^>]*>([^<]+)</div>`)
	if m := locPattern.FindStringSubmatch(content); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract current company/role
	rolePattern := regexp.MustCompile(`<div[^>]*class="[^"]*role[^"]*"[^>]*>([^<]+)</div>`)
	if m := rolePattern.FindStringSubmatch(content); len(m) > 1 {
		role := strings.TrimSpace(m[1])
		if role != "" {
			p.Fields["role"] = role
		}
	}

	companyPattern := regexp.MustCompile(`<div[^>]*class="[^"]*company[^"]*"[^>]*>([^<]+)</div>`)
	if m := companyPattern.FindStringSubmatch(content); len(m) > 1 {
		company := strings.TrimSpace(m[1])
		if company != "" {
			p.Fields["company"] = company
		}
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	return p
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
