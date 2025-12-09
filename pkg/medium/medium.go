// Package medium fetches Medium profile data.
package medium

import (
	"context"
	"errors"
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, fmt.Errorf("fetch failed: %w", err)
	}

	return parseProfile(string(body), normalizedURL, username)
}

func parseProfile(html, url, username string) (*profile.Profile, error) {
	// Detect error pages before attempting to parse
	lowerHTML := strings.ToLower(html)
	errorPatterns := []string{
		"page not found",
		"404",
		"user not found",
		"this page is not available",
		"account suspended",
		"page doesn't exist",
	}
	for _, pattern := range errorPatterns {
		if strings.Contains(lowerHTML, pattern) {
			return nil, errors.New("profile not found (error page detected)")
		}
	}

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

	// Detect if title is just "Medium" (error page indicator)
	if prof.Name == "Medium" || prof.Name == "" {
		return nil, errors.New("profile not found (invalid or missing name)")
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
