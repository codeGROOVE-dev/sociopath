// Package habr fetches Habr profile data.
package habr

import (
	"context"
	"errors"
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

const platform = "habr"

// Match returns true if the URL is a Habr profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	// Match both habr.com and habrahabr.ru
	if !strings.Contains(lower, "habr.com/") && !strings.Contains(lower, "habrahabr.ru/") {
		return false
	}
	// Must contain /users/
	if !strings.Contains(lower, "/users/") {
		return false
	}
	return true
}

// AuthRequired returns false because Habr profiles are public.
func AuthRequired() bool { return false }

// Client handles Habr requests.
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

// New creates a Habr client.
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

// Fetch retrieves a Habr profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	// Normalize to modern habr.com URL
	normalizedURL := fmt.Sprintf("https://habr.com/en/users/%s", username)
	c.logger.InfoContext(ctx, "fetching habr profile", "url", normalizedURL, "username", username)

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

	return parseProfile(content, normalizedURL, username)
}

func parseProfile(html, url, username string) (*profile.Profile, error) {
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract name from title or profile header
	prof.Name = htmlutil.Title(html)
	if prof.Name != "" {
		// Clean up title (remove " - JS / Habr" suffix)
		if idx := strings.Index(prof.Name, " - "); idx != -1 {
			prof.Name = strings.TrimSpace(prof.Name[:idx])
		}
	}

	// Extract bio from "About" section
	// Try pattern: About followed by tm-user-profile__content with span
	aboutPattern := regexp.MustCompile(`(?is)About</dt>.*?<div class="tm-user-profile__content">\s*<span>(.*?)</span>`)
	if matches := aboutPattern.FindStringSubmatch(html); len(matches) > 1 {
		bio := htmlutil.ToMarkdown(matches[1])
		bio = strings.TrimSpace(bio)
		// Remove excessive whitespace
		bio = regexp.MustCompile(`\s+`).ReplaceAllString(bio, " ")
		if bio != "" && len(bio) > 10 {
			prof.Bio = bio
		}
	}

	// If no bio from About, try meta description
	if prof.Bio == "" {
		prof.Bio = htmlutil.Description(html)
	}

	// Extract location - look for "Location" label followed by content
	locationPattern := regexp.MustCompile(`(?is)Location</dt>\s*<dd[^>]*>(.*?)</dd>`)
	if matches := locationPattern.FindStringSubmatch(html); len(matches) > 1 {
		loc := htmlutil.ToMarkdown(matches[1])
		loc = strings.TrimSpace(loc)
		loc = regexp.MustCompile(`\s+`).ReplaceAllString(loc, " ")
		if loc != "" {
			prof.Location = loc
		}
	}

	// Extract contact info (website, GitHub, etc.)
	contactPattern := regexp.MustCompile(`(?i)Contact info[^>]*>(.*?)</div`)
	if matches := contactPattern.FindStringSubmatch(html); len(matches) > 1 {
		// Extract links from contact section
		links := htmlutil.SocialLinks(matches[1])
		for _, link := range links {
			// Skip image URLs
			if strings.Contains(link, "favicon") || strings.Contains(link, "/favicons/") ||
				strings.HasSuffix(link, ".ico") || strings.HasSuffix(link, ".svg") ||
				strings.HasSuffix(link, ".png") || strings.HasSuffix(link, ".jpg") ||
				strings.HasSuffix(link, ".jpeg") || strings.HasSuffix(link, ".gif") {
				continue
			}
			prof.SocialLinks = append(prof.SocialLinks, link)
		}

		// Also check for plain URLs
		urlPattern := regexp.MustCompile(`https?://[^\s<>"]+`)
		urls := urlPattern.FindAllString(matches[1], -1)
		for _, u := range urls {
			u = strings.TrimRight(u, ".,;)")
			// Skip Habr URLs and image URLs
			if strings.Contains(u, "habr.com") || strings.Contains(u, "habrahabr.ru") ||
				strings.Contains(u, "favicon") || strings.Contains(u, "/favicons/") ||
				strings.HasSuffix(u, ".ico") || strings.HasSuffix(u, ".svg") ||
				strings.HasSuffix(u, ".png") || strings.HasSuffix(u, ".jpg") ||
				strings.HasSuffix(u, ".jpeg") || strings.HasSuffix(u, ".gif") {
				continue
			}
			isDuplicate := false
			for _, existing := range prof.SocialLinks {
				if existing == u {
					isDuplicate = true
					break
				}
			}
			if !isDuplicate {
				prof.SocialLinks = append(prof.SocialLinks, u)
			}
		}
	}

	// Extract all social links from page
	pageLinks := htmlutil.SocialLinks(html)
	for _, link := range pageLinks {
		// Skip Habr links, Habr's own social media, retargeting pixels, and favicons/assets
		if strings.Contains(link, "habr.com") || strings.Contains(link, "habrahabr.ru") ||
			strings.Contains(link, "habr_eng") || strings.Contains(link, "habr.eng") ||
			strings.Contains(link, "/rtrg") || // VK retargeting pixel
			strings.Contains(link, "favicon") || strings.Contains(link, "/assets/") ||
			strings.Contains(link, "/favicons/") ||
			strings.HasSuffix(link, ".ico") || strings.HasSuffix(link, ".svg") ||
			strings.HasSuffix(link, ".png") || strings.HasSuffix(link, ".jpg") ||
			strings.HasSuffix(link, ".jpeg") || strings.HasSuffix(link, ".gif") {
			continue
		}
		isDuplicate := false
		for _, existing := range prof.SocialLinks {
			if existing == link {
				isDuplicate = true
				break
			}
		}
		if !isDuplicate {
			prof.SocialLinks = append(prof.SocialLinks, link)
		}
	}

	if prof.Name == "" {
		return nil, errors.New("failed to extract profile name")
	}

	return prof, nil
}

func extractUsername(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")

	// Extract /users/username pattern
	re := regexp.MustCompile(`/users/([^/?#]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
