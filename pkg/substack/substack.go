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

// platformInfo implements profile.Platform for Substack.
type platformInfo struct{}

func (platformInfo) Name() string {
	return platform
}

func (platformInfo) Type() profile.PlatformType {
	return profile.PlatformTypeBlog
}

func (platformInfo) Match(url string) bool {
	return Match(url)
}

func (platformInfo) AuthRequired() bool {
	return AuthRequired()
}

func init() {
	profile.Register(platformInfo{})
}

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

// Patterns for extracting profile data.
var (
	metaAuthorPattern = regexp.MustCompile(`(?i)<meta\s+name=["']author["']\s+content=["']([^"']+)["']`)
	subscriberPattern = regexp.MustCompile(`([\d,]+)\s*(?:subscribers|Subscribers)`)
)

func parseProfile(html, url, username string) (*profile.Profile, error) {
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract author name from meta author tag (most reliable)
	if matches := metaAuthorPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Name = strings.TrimSpace(matches[1])
	}

	// Fallback: extract from title format "Publication Name | Author Name | Substack"
	if prof.Name == "" {
		title := htmlutil.Title(html)
		if title != "" {
			parts := strings.Split(title, " | ")
			if len(parts) >= 2 {
				// Second part is usually the author name
				author := strings.TrimSpace(parts[1])
				if author != "Substack" && author != "" {
					prof.Name = author
				}
			}
			// Clean up "About - Newsletter Name" format
			if prof.Name == "" {
				if idx := strings.Index(title, "About - "); idx != -1 {
					prof.Name = strings.TrimSpace(title[idx+8:])
				}
			}
			// Use title directly if no special format detected
			if prof.Name == "" && title != "Substack" {
				prof.Name = strings.TrimSpace(title)
			}
		}
	}

	// Extract bio/description
	prof.Bio = htmlutil.Description(html)

	// Try to extract subscriber count
	if matches := subscriberPattern.FindStringSubmatch(html); len(matches) > 1 {
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
