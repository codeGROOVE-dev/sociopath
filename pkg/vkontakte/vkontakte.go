// Package vkontakte provides VKontakte profile fetching with optional authentication.
package vkontakte

import (
	"context"
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

const platform = "vkontakte"

// Match returns true if the URL is a VKontakte profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "vk.com/")
}

// AuthRequired returns false because VKontakte doesn't strictly require auth, but cookies help with bot detection.
func AuthRequired() bool { return false }

// Client handles VKontakte requests.
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

// New creates a VKontakte client.
// Cookies are optional but help bypass bot detection.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	// Try to get cookies but don't fail if not available
	var sources []auth.Source
	if len(cfg.cookies) > 0 {
		sources = append(sources, auth.NewStaticSource(cfg.cookies))
	}
	sources = append(sources, auth.EnvSource{})
	if cfg.browserCookies {
		sources = append(sources, auth.NewBrowserSource(cfg.logger))
	}

	cookies, _ := auth.ChainSources(ctx, platform, sources...) //nolint:errcheck // cookies are optional

	var httpClient *http.Client
	if len(cookies) > 0 {
		jar, err := auth.NewCookieJar("vk.com", cookies)
		if err == nil {
			httpClient = &http.Client{Jar: jar, Timeout: 10 * time.Second}
			cfg.logger.InfoContext(ctx, "vkontakte client created with cookies", "cookie_count", len(cookies))
		}
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
		cfg.logger.InfoContext(ctx, "vkontakte client created without cookies (may encounter bot detection)")
	}

	return &Client{
		httpClient: httpClient,
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a VKontakte profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	// Normalize URL
	if !strings.HasPrefix(urlStr, "http") {
		urlStr = "https://vk.com/" + strings.TrimPrefix(urlStr, "vk.com/")
	}

	c.logger.InfoContext(ctx, "fetching vkontakte profile", "url", urlStr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}

	setHeaders(req)

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return parseProfile(string(body), urlStr)
}

func setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
}

func parseProfile(html, url string) (*profile.Profile, error) {
	// Check for bot detection page
	if strings.Contains(html, "У вас большие запросы") || strings.Contains(html, "You are making too many requests") {
		return nil, errors.New("VK bot detection triggered - try using browser cookies")
	}

	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: extractUsername(url),
		Fields:   make(map[string]string),
	}

	// Extract name from title or meta tags
	prof.Name = htmlutil.Title(html)
	if prof.Name != "" {
		// Clean up VK title format "Name | VK"
		if idx := strings.Index(prof.Name, " | VK"); idx != -1 {
			prof.Name = strings.TrimSpace(prof.Name[:idx])
		}
	}

	// Extract bio/description
	prof.Bio = htmlutil.Description(html)

	// Extract birthday (Russian: День рождения)
	birthdayPattern := regexp.MustCompile(`(?i)birthday[^>]*>([^<]+)</|день рождения[^>]*>([^<]+)</`)
	if matches := birthdayPattern.FindStringSubmatch(html); len(matches) > 1 {
		for i := 1; i < len(matches); i++ {
			if matches[i] != "" {
				birthday := strings.TrimSpace(matches[i])
				if birthday != "" {
					prof.Fields["birthday"] = birthday
					break
				}
			}
		}
	}

	// Extract city - look for VK profile info row patterns
	// VK uses patterns like <span class="ProfileInfoRow__content">City Name</span>
	prof.Location = extractLocation(html)

	// Extract education (Russian: Образование)
	eduPattern := regexp.MustCompile(`(?i)education[^>]*>([^<]+)</|образование[^>]*>([^<]+)</|studied at[^>]*>([^<]+)</|учился[^>]*>([^<]+)</`)
	if matches := eduPattern.FindStringSubmatch(html); len(matches) > 1 {
		for i := 1; i < len(matches); i++ {
			if matches[i] != "" {
				edu := strings.TrimSpace(matches[i])
				if edu != "" {
					prof.Fields["education"] = edu
					break
				}
			}
		}
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(html)

	// Filter out VK's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "vk.com") {
			filtered = append(filtered, link)
		}
	}
	prof.SocialLinks = filtered

	return prof, nil
}

const maxLocationLen = 64

// Pre-compiled location patterns.
var locationPatterns = []*regexp.Regexp{
	// ProfileInfoRow with city/город label
	regexp.MustCompile(`(?i)ProfileInfoRow[^>]*город[^>]*>[^<]*<[^>]*class="[^"]*content[^"]*"[^>]*>([^<]+)</`),
	regexp.MustCompile(`(?i)ProfileInfoRow[^>]*city[^>]*>[^<]*<[^>]*class="[^"]*content[^"]*"[^>]*>([^<]+)</`),
	// General profile info content after city label - match <span class="city">Value</span>
	regexp.MustCompile(`(?i)<[^>]+class="[^"]*\bcity\b[^"]*"[^>]*>([^<]+)</`),
	regexp.MustCompile(`(?i)<[^>]+class="город"[^>]*>([^<]+)</`),
	// Hometown patterns
	regexp.MustCompile(`(?i)<[^>]+class="[^"]*\bhometown\b[^"]*"[^>]*>([^<]+)</`),
	regexp.MustCompile(`(?i)родной город[^>]*>([^<]+)</`),
}

// extractLocation extracts location from VK HTML, with validation.
func extractLocation(html string) string {
	for _, pattern := range locationPatterns {
		if matches := pattern.FindStringSubmatch(html); len(matches) > 1 {
			loc := strings.TrimSpace(matches[1])
			if isValidLocation(loc) {
				return truncateLocation(loc)
			}
		}
	}
	return ""
}

// isValidLocation checks if the extracted location is valid (not CSS/code).
func isValidLocation(loc string) bool {
	if loc == "" {
		return false
	}
	// Reject if it looks like CSS/code
	cssIndicators := []string{"{", "}", "var(", "px", "rgb", "rgba", "color:", "margin:", "padding:", "display:", "font-"}
	for _, indicator := range cssIndicators {
		if strings.Contains(loc, indicator) {
			return false
		}
	}
	// Reject if too long (real locations are rarely > 64 chars)
	if len(loc) > maxLocationLen {
		return false
	}
	return true
}

// truncateLocation truncates location to maximum length.
func truncateLocation(loc string) string {
	if len(loc) <= maxLocationLen {
		return loc
	}
	return loc[:maxLocationLen]
}

func extractUsername(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "www.")

	// Extract vk.com/username pattern
	re := regexp.MustCompile(`vk\.com/([^/?#]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
