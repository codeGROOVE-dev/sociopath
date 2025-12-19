// Package ohjelmointiputka fetches Ohjelmointiputka profile data.
package ohjelmointiputka

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "ohjelmointiputka"

// platformInfo implements profile.Platform for Ohjelmointiputka.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is an Ohjelmointiputka profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "ohjelmointiputka.net") {
		return false
	}
	// Match profile URLs: /kayttajat/profiili/username
	if strings.Contains(lower, "/kayttajat/profiili/") {
		return true
	}
	return false
}

// AuthRequired returns false because Ohjelmointiputka profiles are public.
func AuthRequired() bool { return false }

// Client handles Ohjelmointiputka requests.
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

// New creates an Ohjelmointiputka client.
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

// Fetch retrieves an Ohjelmointiputka profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	normalizedURL := fmt.Sprintf("https://www.ohjelmointiputka.net/kayttajat/profiili/%s", username)
	c.logger.InfoContext(ctx, "fetching ohjelmointiputka profile", "url", normalizedURL, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(string(body), normalizedURL, username)
}

func parseProfile(html, url, username string) (*profile.Profile, error) {
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract title
	prof.PageTitle = htmlutil.Title(html)

	// Extract display name - usually the username is the display name
	// Try to find a display name in the profile header
	namePattern := regexp.MustCompile(`(?i)<h[1-3][^>]*>\s*([^<]+)\s*</h[1-3]>`)
	if matches := namePattern.FindStringSubmatch(html); len(matches) > 1 {
		name := strings.TrimSpace(matches[1])
		if name != "" && !strings.Contains(strings.ToLower(name), "error") {
			prof.DisplayName = name
		}
	}

	// If no display name found, use username
	if prof.DisplayName == "" {
		prof.DisplayName = username
	}

	// Extract bio/description from meta or profile section
	prof.Bio = htmlutil.Description(html)

	// Look for bio in profile content
	bioPattern := regexp.MustCompile(`(?is)<div[^>]*class="[^"]*profile[^"]*"[^>]*>(.*?)</div>`)
	if matches := bioPattern.FindStringSubmatch(html); len(matches) > 1 {
		bio := htmlutil.StripTags(matches[1])
		bio = strings.TrimSpace(bio)
		bio = regexp.MustCompile(`\s+`).ReplaceAllString(bio, " ")
		if bio != "" && len(bio) > 10 {
			prof.Bio = bio
		}
	}

	// Extract social links from the page
	pageLinks := htmlutil.SocialLinks(html)
	for _, link := range pageLinks {
		// Skip internal links and assets
		if strings.Contains(link, "ohjelmointiputka.net") ||
			strings.Contains(link, "favicon") ||
			strings.HasSuffix(link, ".ico") || strings.HasSuffix(link, ".svg") ||
			strings.HasSuffix(link, ".png") || strings.HasSuffix(link, ".jpg") {
			continue
		}
		if !slices.Contains(prof.SocialLinks, link) {
			prof.SocialLinks = append(prof.SocialLinks, link)
		}
	}

	// Extract posts count if available
	postsPattern := regexp.MustCompile(`(?i)(\d+)\s+(viesti|post|message)`)
	if matches := postsPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["posts"] = matches[1]
	}

	if prof.DisplayName == "" {
		return nil, errors.New("failed to extract profile name")
	}

	return prof, nil
}

func extractUsername(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "www.")

	// Extract /kayttajat/profiili/username pattern
	re := regexp.MustCompile(`/kayttajat/profiili/([^/?#]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
