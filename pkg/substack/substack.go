// Package substack fetches Substack author profile data.
package substack

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

const platform = "substack"

// Match returns true if the URL is a Substack profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, ".substack.com")
}

// AuthRequired returns false because Substack profiles are public.
func AuthRequired() bool { return false }

// Client handles Substack requests.
type Client struct {
	httpClient *http.Client
	cache      *httpcache.Cache
	logger     *slog.Logger
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache  *httpcache.Cache
	logger *slog.Logger
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache *httpcache.Cache) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates a Substack client.
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

// Fetch retrieves a Substack profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	// Normalize URL to /about page for author info
	normalizedURL := fmt.Sprintf("https://%s.substack.com/about", username)
	c.logger.InfoContext(ctx, "fetching substack profile", "url", normalizedURL, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(string(body), urlStr, username)
}

func parseProfile(html, url, username string) (*profile.Profile, error) {
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract name from title or meta tags
	prof.Name = htmlutil.Title(html)
	if prof.Name != "" {
		// Clean up "About - Newsletter Name"
		if idx := strings.Index(prof.Name, "About - "); idx != -1 {
			prof.Name = strings.TrimSpace(prof.Name[idx+8:])
		}
	}

	// Extract bio/description
	prof.Bio = htmlutil.Description(html)

	// Try to extract subscriber count
	subPattern := regexp.MustCompile(`([\d,]+)\s*(?:subscribers|Subscribers)`)
	if matches := subPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["subscribers"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(html)

	// Filter out Substack's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "substack.com") {
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

	// Extract username.substack.com pattern
	re := regexp.MustCompile(`^([^.]+)\.substack\.com`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
