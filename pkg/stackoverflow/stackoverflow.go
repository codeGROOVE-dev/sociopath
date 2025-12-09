// Package stackoverflow fetches StackOverflow user profile data.
package stackoverflow

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
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

	// Extract name from title - format: "User Jon Skeet - Stack Overflow"
	title := htmlutil.Title(content)
	if name, found := strings.CutPrefix(title, "User "); found {
		if idx := strings.Index(name, " - "); idx != -1 {
			p.Name = strings.TrimSpace(name[:idx])
		}
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
		return m[1]
	}
	return ""
}
