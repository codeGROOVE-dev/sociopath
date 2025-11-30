// Package youtube fetches YouTube channel/user profile data.
package youtube

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

const platform = "youtube"

// Match returns true if the URL is a YouTube channel/user URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return (strings.Contains(lower, "youtube.com/") &&
		(strings.Contains(lower, "/@") ||
			strings.Contains(lower, "/channel/") ||
			strings.Contains(lower, "/c/") ||
			strings.Contains(lower, "/user/")))
}

// AuthRequired returns false because YouTube channels are public.
func AuthRequired() bool { return false }

// Client handles YouTube requests.
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

// New creates a YouTube client.
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

// Fetch retrieves a YouTube channel profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	// Normalize URL (keep as-is since YouTube has multiple URL formats)
	normalizedURL := urlStr
	if !strings.HasPrefix(normalizedURL, "http") {
		normalizedURL = "https://www.youtube.com/" + strings.TrimPrefix(urlStr, "youtube.com/")
	}

	c.logger.InfoContext(ctx, "fetching youtube profile", "url", normalizedURL)

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
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

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

	return parseProfile(content, normalizedURL)
}

func parseProfile(html, url string) (*profile.Profile, error) { //nolint:unparam // error return part of interface pattern
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: extractUsername(url),
		Fields:   make(map[string]string),
	}

	// Extract name from title or meta tags
	prof.Name = htmlutil.Title(html)
	if prof.Name != "" {
		// Clean up "Channel Name - YouTube"
		if idx := strings.Index(prof.Name, " - YouTube"); idx != -1 {
			prof.Name = strings.TrimSpace(prof.Name[:idx])
		}
	}

	// Extract description
	prof.Bio = htmlutil.Description(html)

	// Try to extract subscriber count
	subPattern := regexp.MustCompile(`([\d.]+[KMB]?)\s*(?:subscribers|Subscribers)`)
	if matches := subPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["subscribers"] = matches[1]
	}

	// Try to extract video count
	videoPattern := regexp.MustCompile(`([\d,]+)\s*(?:videos|Videos)`)
	if matches := videoPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["videos"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(html)

	// Filter out YouTube's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "youtube.com") &&
			!strings.Contains(link, "youtu.be") &&
			!strings.Contains(link, "google.com") {
			filtered = append(filtered, link)
		}
	}
	prof.SocialLinks = filtered

	if prof.Name == "" {
		prof.Name = prof.Username
	}

	return prof, nil
}

func extractUsername(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "www.")

	// Extract various YouTube URL patterns
	// @handle format
	re := regexp.MustCompile(`youtube\.com/@([^/?#]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	// /c/channel format
	re2 := regexp.MustCompile(`youtube\.com/c/([^/?#]+)`)
	if matches := re2.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	// /user/ format
	re3 := regexp.MustCompile(`youtube\.com/user/([^/?#]+)`)
	if matches := re3.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	// /channel/ format (ID)
	re4 := regexp.MustCompile(`youtube\.com/channel/([^/?#]+)`)
	if matches := re4.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
