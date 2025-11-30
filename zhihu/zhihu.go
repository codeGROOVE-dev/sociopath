// Package zhihu fetches Zhihu (知乎) profile data.
package zhihu

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

const platform = "zhihu"

// Match returns true if the URL is a Zhihu profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "zhihu.com/people/")
}

// AuthRequired returns false because Zhihu profiles are public (but may have bot detection).
func AuthRequired() bool { return false }

// Client handles Zhihu requests.
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

// New creates a Zhihu client.
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

// Fetch retrieves a Zhihu profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	normalizedURL := fmt.Sprintf("https://www.zhihu.com/people/%s", username)
	c.logger.InfoContext(ctx, "fetching zhihu profile", "url", normalizedURL, "username", username)

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

	return parseProfile(content, normalizedURL, username)
}

func parseProfile(html, url, username string) (*profile.Profile, error) { //nolint:unparam // error return part of interface pattern
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract name from title or meta tags
	prof.Name = htmlutil.Title(html)
	if prof.Name != "" {
		// Clean up "Name - 知乎"
		prof.Name = strings.TrimSuffix(prof.Name, " - 知乎") //nolint:gosmopolitan // Chinese text is intentional for Zhihu
		prof.Name = strings.TrimSpace(prof.Name)
	}

	// Extract bio/description
	prof.Bio = htmlutil.Description(html)

	// Try to extract follower count
	followerPattern := regexp.MustCompile(`(\d+)\s*(?:关注者|followers)`) //nolint:gosmopolitan // Chinese text is intentional for Zhihu
	if matches := followerPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["followers"] = matches[1]
	}

	// Try to extract answer/article counts
	answerPattern := regexp.MustCompile(`(\d+)\s*(?:回答|answers)`) //nolint:gosmopolitan // Chinese text is intentional for Zhihu
	if matches := answerPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["answers"] = matches[1]
	}

	articlePattern := regexp.MustCompile(`(\d+)\s*(?:文章|articles)`) //nolint:gosmopolitan // Chinese text is intentional for Zhihu
	if matches := articlePattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["articles"] = matches[1]
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(html)

	// Filter out Zhihu's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "zhihu.com") {
			filtered = append(filtered, link)
		}
	}
	prof.SocialLinks = filtered

	if prof.Name == "" {
		prof.Name = username
	}

	return prof, nil
}

func extractUsername(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")

	// Extract zhihu.com/people/username pattern
	re := regexp.MustCompile(`zhihu\.com/people/([^/?#]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
