// Package bilibili fetches Bilibili (哔哩哔哩) user profile data.
package bilibili

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/cache"
	"github.com/codeGROOVE-dev/sociopath/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/profile"
)

const platform = "bilibili"

// Match returns true if the URL is a Bilibili user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "space.bilibili.com/") ||
		strings.Contains(lower, "bilibili.com/") && regexp.MustCompile(`/\d+`).MatchString(lower)
}

// AuthRequired returns false because Bilibili profiles are public (but may have bot detection).
func AuthRequired() bool { return false }

// Client handles Bilibili requests.
type Client struct {
	httpClient *http.Client
	cache      cache.HTTPCache
	logger     *slog.Logger
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache  cache.HTTPCache
	logger *slog.Logger
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache cache.HTTPCache) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates a Bilibili client.
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

// Fetch retrieves a Bilibili profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	userID := extractUserID(urlStr)
	if userID == "" {
		return nil, fmt.Errorf("could not extract user ID from: %s", urlStr)
	}

	normalizedURL := fmt.Sprintf("https://space.bilibili.com/%s", userID)
	c.logger.InfoContext(ctx, "fetching bilibili profile", "url", normalizedURL, "userid", userID)

	// Check cache
	var content string
	if c.cache != nil {
		if data, _, _, found := c.cache.Get(ctx, normalizedURL); found {
			content = string(data)
		}
	}

	if content == "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }() //nolint:errcheck // error ignored intentionally

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5MB limit
		if err != nil {
			return nil, err
		}
		content = string(body)

		// Cache response
		if c.cache != nil {
			_ = c.cache.SetAsync(ctx, normalizedURL, body, "", nil) //nolint:errcheck // error ignored intentionally
		}
	}

	return parseProfile(content, normalizedURL, userID)
}

func parseProfile(html, url, userID string) (*profile.Profile, error) { //nolint:unparam // error return part of interface pattern
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: userID,
		Fields:   make(map[string]string),
	}

	// Extract name from title or meta tags
	prof.Name = htmlutil.Title(html)
	if prof.Name != "" {
		// Clean up "Name的个人空间_哔哩哔哩_bilibili"
		prof.Name = strings.TrimSuffix(prof.Name, "的个人空间_哔哩哔哩_bilibili") //nolint:gosmopolitan // Chinese text is intentional for Bilibili
		prof.Name = strings.TrimSuffix(prof.Name, "的个人空间")               //nolint:gosmopolitan // Chinese text is intentional for Bilibili
		prof.Name = strings.TrimSuffix(prof.Name, "_哔哩哔哩_bilibili")      //nolint:gosmopolitan // Chinese text is intentional for Bilibili
		prof.Name = strings.TrimSpace(prof.Name)
	}

	// Extract bio/description
	prof.Bio = htmlutil.Description(html)

	// Try to extract follower count (粉丝)
	followerPattern := regexp.MustCompile(`(\d+(?:\.\d+)?[万千]?)\s*(?:粉丝|fans)`) //nolint:gosmopolitan // Chinese text is intentional for Bilibili
	if matches := followerPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["followers"] = matches[1]
	}

	// Try to extract following count (关注)
	followingPattern := regexp.MustCompile(`(\d+)\s*(?:关注|following)`) //nolint:gosmopolitan // Chinese text is intentional for Bilibili
	if matches := followingPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["following"] = matches[1]
	}

	// Try to extract video count
	videoPattern := regexp.MustCompile(`(\d+)\s*(?:投稿|videos)`) //nolint:gosmopolitan // Chinese text is intentional for Bilibili
	if matches := videoPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["videos"] = matches[1]
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(html)

	// Filter out Bilibili's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "bilibili.com") &&
			!strings.Contains(link, "bilibili.cn") {
			filtered = append(filtered, link)
		}
	}
	prof.SocialLinks = filtered

	if prof.Name == "" {
		prof.Name = userID
	}

	return prof, nil
}

func extractUserID(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")

	// Extract space.bilibili.com/12345 pattern
	re := regexp.MustCompile(`(?:space\.)?bilibili\.com/(\d+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
