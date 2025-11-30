// Package reddit fetches Reddit user profile data.
package reddit

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

const platform = "reddit"

// Match returns true if the URL is a Reddit user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "reddit.com/user/") ||
		strings.Contains(lower, "reddit.com/u/")
}

// AuthRequired returns false because Reddit profiles are public.
func AuthRequired() bool { return false }

// Client handles Reddit requests.
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

// New creates a Reddit client.
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

// Fetch retrieves a Reddit profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	// Normalize to old.reddit.com for simpler HTML parsing
	normalizedURL := fmt.Sprintf("https://old.reddit.com/user/%s", username)
	c.logger.InfoContext(ctx, "fetching reddit profile", "url", normalizedURL, "username", username)

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

	return parseProfile(content, urlStr, username)
}

func parseProfile(html, url, username string) (*profile.Profile, error) { //nolint:unparam // error return part of interface pattern
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract name from title
	prof.Name = htmlutil.Title(html)
	if prof.Name != "" {
		// Clean up "overview for username - Reddit"
		prof.Name = strings.TrimPrefix(prof.Name, "overview for ")
		if idx := strings.Index(prof.Name, " - Reddit"); idx != -1 {
			prof.Name = strings.TrimSpace(prof.Name[:idx])
		}
	}
	if prof.Name == "" {
		prof.Name = username
	}

	// Extract karma
	karmaPattern := regexp.MustCompile(`(\d+(?:,\d+)?)\s*(?:post|link)\s*karma`)
	if matches := karmaPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["post_karma"] = strings.ReplaceAll(matches[1], ",", "")
	}

	commentKarmaPattern := regexp.MustCompile(`(\d+(?:,\d+)?)\s*comment\s*karma`)
	if matches := commentKarmaPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["comment_karma"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract cake day (account creation date)
	cakeDayPattern := regexp.MustCompile(`(?i)redditor since.*?(\d{4})`)
	if matches := cakeDayPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["joined_year"] = matches[1]
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(html)

	// Filter out Reddit's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "reddit.com") &&
			!strings.Contains(link, "redd.it") {
			filtered = append(filtered, link)
		}
	}
	prof.SocialLinks = filtered

	return prof, nil
}

func extractUsername(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")

	// Extract reddit.com/user/username or reddit.com/u/username
	re := regexp.MustCompile(`reddit\.com/(?:user|u)/([^/?#]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
