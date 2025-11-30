// Package devto fetches Dev.to user profile data.
package devto

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/profile"
)

const platform = "devto"

// Match returns true if the URL is a Dev.to profile URL.
func Match(urlStr string) bool {
	return strings.Contains(strings.ToLower(urlStr), "dev.to/")
}

// AuthRequired returns false because Dev.to profiles are public.
func AuthRequired() bool { return false }

// Client handles Dev.to requests.
type Client struct {
	httpClient *http.Client
	cache      profile.HTTPCache
	logger     *slog.Logger
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache  profile.HTTPCache
	logger *slog.Logger
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(cache profile.HTTPCache) Option {
	return func(c *config) { c.cache = cache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates a Dev.to client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves a Dev.to profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching devto profile", "url", urlStr, "username", username)

	// Check cache
	if c.cache != nil {
		if data, _, _, found := c.cache.Get(ctx, urlStr); found {
			return parseHTML(data, urlStr, username), nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // error ignored intentionally

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	// Cache response (async, errors intentionally ignored)
	if c.cache != nil {
		_ = c.cache.SetAsync(ctx, urlStr, body, "", nil) //nolint:errcheck // async, error ignored
	}

	return parseHTML(body, urlStr, username), nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Extract name from crayons-title h1
	namePattern := regexp.MustCompile(`<h1[^>]*class="[^"]*crayons-title[^"]*"[^>]*>\s*([^<]+)\s*</h1>`)
	if m := namePattern.FindStringSubmatch(content); len(m) > 1 {
		p.Name = strings.TrimSpace(html.UnescapeString(m[1]))
	}

	// Fallback to og:title
	if p.Name == "" {
		title := htmlutil.Title(content)
		if idx := strings.Index(title, " - DEV"); idx > 0 {
			p.Name = strings.TrimSpace(title[:idx])
		}
	}

	// Extract bio from meta description
	p.Bio = htmlutil.Description(content)

	// Extract location
	locPattern := regexp.MustCompile(`(?i)location[^>]*>[^<]*</[^>]+>\s*<[^>]+>([A-Za-z][^<]{2,50})</`)
	if m := locPattern.FindStringSubmatch(content); len(m) > 1 {
		loc := strings.TrimSpace(html.UnescapeString(m[1]))
		if !strings.Contains(strings.ToLower(loc), "joined") {
			p.Location = loc
			p.Fields["location"] = loc
		}
	}

	// Extract website
	websitePattern := regexp.MustCompile(`(?i)<a[^>]+href=["'](https?://[^"']+)["'][^>]*>\s*Website\s*</a>`)
	if m := websitePattern.FindStringSubmatch(content); len(m) > 1 {
		p.Website = m[1]
		p.Fields["website"] = m[1]
	}

	// Extract Twitter
	twitterPattern := regexp.MustCompile(`<a[^>]+href=["'](https?://(?:twitter\.com|x\.com)/[^"']+)["']`)
	if m := twitterPattern.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["twitter"] = m[1]
	}

	// Extract GitHub
	githubPattern := regexp.MustCompile(`<a[^>]+href=["'](https?://github\.com/[^"']+)["']`)
	if m := githubPattern.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["github"] = m[1]
	}

	p.SocialLinks = htmlutil.SocialLinks(content)

	return p
}

func extractUsername(urlStr string) string {
	if idx := strings.Index(urlStr, "dev.to/"); idx != -1 {
		username := urlStr[idx+len("dev.to/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}
	return ""
}
