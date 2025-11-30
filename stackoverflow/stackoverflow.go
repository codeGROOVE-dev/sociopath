// Package stackoverflow fetches StackOverflow user profile data.
package stackoverflow

import (
	"context"
	"crypto/tls"
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

const platform = "stackoverflow"

// Match returns true if the URL is a StackOverflow profile URL.
func Match(urlStr string) bool {
	return strings.Contains(strings.ToLower(urlStr), "stackoverflow.com/users/")
}

// AuthRequired returns false because StackOverflow profiles are public.
func AuthRequired() bool { return false }

// Client handles StackOverflow requests.
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

// New creates a StackOverflow client.
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

// Fetch retrieves a StackOverflow profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)

	c.logger.InfoContext(ctx, "fetching stackoverflow profile", "url", urlStr, "username", username)

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
		Name:          username,
		Fields:        make(map[string]string),
	}

	// Extract location
	locPattern := regexp.MustCompile(`<div[^>]*class="[^"]*wmx2[^"]*truncate[^"]*"[^>]*title="([^"]+)"`)
	if m := locPattern.FindStringSubmatch(content); len(m) > 1 {
		loc := strings.TrimSpace(m[1])
		if len(loc) > 3 && len(loc) < 100 {
			p.Location = loc
			p.Fields["location"] = loc
		}
	}

	// Extract reputation
	repPattern := regexp.MustCompile(`(?i)<div[^>]*class="[^"]*fs-title[^"]*"[^>]*>\s*([\d,]+)\s*</div>\s*<div[^>]*>reputation</div>`)
	if m := repPattern.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["reputation"] = m[1]
	}

	// Extract top tags
	tagPattern := regexp.MustCompile(`(?i)<a[^>]*class="[^"]*post-tag[^"]*"[^>]*>([^<]+)</a>`)
	tagMatches := tagPattern.FindAllStringSubmatch(content, 5)
	var tags []string
	for _, m := range tagMatches {
		if len(m) > 1 && len(tags) < 5 {
			tags = append(tags, strings.TrimSpace(m[1]))
		}
	}
	if len(tags) > 0 {
		p.Fields["top_tags"] = strings.Join(tags, ", ")
	}

	// Use bio field for location display
	if p.Location != "" {
		p.Bio = p.Location
	}

	p.SocialLinks = htmlutil.SocialLinks(content)

	return p
}

func extractUsername(urlStr string) string {
	re := regexp.MustCompile(`/users/\d+/([^/?]+)`)
	if m := re.FindStringSubmatch(urlStr); len(m) > 1 {
		return strings.ReplaceAll(m[1], "-", " ")
	}
	return ""
}
