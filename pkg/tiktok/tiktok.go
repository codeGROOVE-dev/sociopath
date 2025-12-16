// Package tiktok provides TikTok profile fetching.
package tiktok

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/auth"
	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "tiktok"

// platformInfo implements profile.Platform for TikTok.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeVideo }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a TikTok profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "tiktok.com/@")
}

// AuthRequired returns false because TikTok works without authentication.
func AuthRequired() bool { return false }

// Client handles TikTok requests.
type Client struct {
	httpClient *http.Client
	cache      httpcache.Cacher
	logger     *slog.Logger
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cookies        map[string]string
	cache          httpcache.Cacher
	logger         *slog.Logger
	browserCookies bool
}

// WithCookies sets explicit cookie values.
func WithCookies(cookies map[string]string) Option {
	return func(c *config) { c.cookies = cookies }
}

// WithBrowserCookies enables reading cookies from browser stores.
func WithBrowserCookies() Option {
	return func(c *config) { c.browserCookies = true }
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache httpcache.Cacher) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates a TikTok client.
// Cookies are optional and will be used if provided via: WithCookies > environment variables > browser.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	var sources []auth.Source
	if len(cfg.cookies) > 0 {
		sources = append(sources, auth.NewStaticSource(cfg.cookies))
	}
	sources = append(sources, auth.EnvSource{})
	if cfg.browserCookies {
		sources = append(sources, auth.NewBrowserSource(cfg.logger))
	}

	cookies, err := auth.ChainSources(ctx, platform, sources...)
	if err != nil {
		cfg.logger.Debug("cookie retrieval failed, continuing without auth", "error", err)
	}

	var jar http.CookieJar
	if len(cookies) > 0 {
		jar, err = auth.NewCookieJar("tiktok.com", cookies)
		if err != nil {
			return nil, fmt.Errorf("cookie jar creation failed: %w", err)
		}
		cfg.logger.InfoContext(ctx, "tiktok client created with cookies", "cookie_count", len(cookies))
	} else {
		cfg.logger.InfoContext(ctx, "tiktok client created without cookies")
	}

	return &Client{
		httpClient: &http.Client{Jar: jar, Timeout: 10 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a TikTok profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	profileURL := "https://www.tiktok.com/@" + username
	c.logger.InfoContext(ctx, "fetching tiktok profile", "url", profileURL, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}

	setHeaders(req)

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return c.parseProfile(ctx, body, profileURL)
}

func setHeaders(req *http.Request) {
	// User-Agent matching Chrome 120 on macOS
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
}

func (c *Client) parseProfile(ctx context.Context, body []byte, profileURL string) (*profile.Profile, error) {
	content := string(body)

	// Extract JSON data from __UNIVERSAL_DATA_FOR_REHYDRATION__ script tag
	jsonData := extractUniversalData(content)
	if jsonData == "" {
		c.logger.Debug("failed to find __UNIVERSAL_DATA_FOR_REHYDRATION__ in page", "url", profileURL)
		return nil, errors.New("could not find __UNIVERSAL_DATA_FOR_REHYDRATION__ in page")
	}

	c.logger.Debug("found __UNIVERSAL_DATA_FOR_REHYDRATION__", "length", len(jsonData))

	var data map[string]any
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return nil, fmt.Errorf("failed to parse __UNIVERSAL_DATA_FOR_REHYDRATION__: %w", err)
	}

	// Navigate: data["__DEFAULT_SCOPE__"]["webapp.user-detail"]["userInfo"]["user"]
	defaultScope, ok := data["__DEFAULT_SCOPE__"].(map[string]any)
	if !ok {
		return nil, errors.New("no __DEFAULT_SCOPE__ in data")
	}

	userDetail, ok := defaultScope["webapp.user-detail"].(map[string]any)
	if !ok {
		return nil, errors.New("no webapp.user-detail in __DEFAULT_SCOPE__")
	}

	userInfo, ok := userDetail["userInfo"].(map[string]any)
	if !ok {
		return nil, errors.New("no userInfo in webapp.user-detail")
	}

	user, ok := userInfo["user"].(map[string]any)
	if !ok {
		return nil, errors.New("no user in userInfo")
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           profileURL,
		Authenticated: true,
		Fields:        make(map[string]string),
	}

	// Extract fields
	if username, ok := user["uniqueId"].(string); ok {
		p.Username = username
	}
	if name, ok := user["nickname"].(string); ok {
		p.DisplayName = name
	}
	if avatarURL, ok := user["avatarLarger"].(string); ok {
		p.AvatarURL = avatarURL
	} else if avatarURL, ok := user["avatarMedium"].(string); ok {
		p.AvatarURL = avatarURL
	}
	if signature, ok := user["signature"].(string); ok {
		p.Bio = signature
	}

	// Extract social links from page content
	p.SocialLinks = htmlutil.SocialLinks(content)
	p.SocialLinks = filterSamePlatformLinks(p.SocialLinks)

	c.logger.InfoContext(ctx, "tiktok profile parsed",
		"username", p.Username,
		"name", p.DisplayName,
		"bio_length", len(p.Bio))

	return p, nil
}

// extractUniversalData extracts the JSON content from the __UNIVERSAL_DATA_FOR_REHYDRATION__ script tag.
func extractUniversalData(content string) string {
	// Match: <script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application/json">{...}</script>
	re := regexp.MustCompile(`<script[^>]*id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>([^<]+)</script>`)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractUsername extracts the username from a TikTok URL or @username string.
func extractUsername(s string) string {
	if strings.Contains(s, "/") {
		re := regexp.MustCompile(`tiktok\.com/@([^/?]+)`)
		if m := re.FindStringSubmatch(s); len(m) > 1 {
			return m[1]
		}
	}
	return strings.TrimPrefix(s, "@")
}

// filterSamePlatformLinks removes TikTok URLs from the social links list.
func filterSamePlatformLinks(links []string) []string {
	var filtered []string
	for _, link := range links {
		if !Match(link) {
			filtered = append(filtered, link)
		}
	}
	return filtered
}
