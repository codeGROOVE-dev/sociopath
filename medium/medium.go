// Package medium fetches Medium profile data.
package medium

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

const platform = "medium"

// Match returns true if the URL is a Medium profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	// Match medium.com/@username or custom domains
	return strings.Contains(lower, "medium.com/@") ||
		(strings.Contains(lower, "medium.com") && strings.Contains(lower, "/user/"))
}

// AuthRequired returns false because Medium profiles are public.
func AuthRequired() bool { return false }

// Client handles Medium requests.
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

// New creates a Medium client.
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

// Fetch retrieves a Medium profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	// Normalize URL
	normalizedURL := fmt.Sprintf("https://medium.com/@%s", username)
	c.logger.InfoContext(ctx, "fetching medium profile", "url", normalizedURL, "username", username)

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
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

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
		// Clean up Medium title format "Name - Medium"
		if idx := strings.Index(prof.Name, " - Medium"); idx != -1 {
			prof.Name = strings.TrimSpace(prof.Name[:idx])
		} else if idx := strings.Index(prof.Name, " – Medium"); idx != -1 {
			prof.Name = strings.TrimSpace(prof.Name[:idx])
		}
	}

	// Extract bio/description
	prof.Bio = htmlutil.Description(html)

	// Try to extract follower count
	followerPattern := regexp.MustCompile(`(\d+(?:\.\d+)?[KMk]?)\s*(?:Followers|followers)`)
	if matches := followerPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["followers"] = matches[1]
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(html)

	// Filter out Medium's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "medium.com") {
			filtered = append(filtered, link)
		}
	}
	prof.SocialLinks = filtered

	// If we still don't have a name, return error
	if prof.Name == "" {
		prof.Name = username // Fallback to username
	}

	return prof, nil
}

func extractUsername(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")

	// Extract medium.com/@username pattern
	re := regexp.MustCompile(`medium\.com/@([^/?#]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	// Also try /user/ pattern
	re2 := regexp.MustCompile(`medium\.com/user/([^/?#]+)`)
	if matches := re2.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
