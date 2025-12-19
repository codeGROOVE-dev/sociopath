// Package crackmes fetches Crackmes.one (reverse engineering challenges) user profile data.
package crackmes

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
	"golang.org/x/net/html"
)

const platform = "crackmes"

// platformInfo implements profile.Platform for Crackmes.one.
type platformInfo struct{}

func (platformInfo) Name() string {
	return platform
}

func (platformInfo) Type() profile.PlatformType {
	return profile.PlatformTypeSecurity
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

var usernamePattern = regexp.MustCompile(`(?i)crackmes\.one/user/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Crackmes.one user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "crackmes.one/user/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Crackmes.one profiles are public.
func AuthRequired() bool { return false }

// Client handles Crackmes.one requests.
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

// New creates a Crackmes.one client.
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

// Fetch retrieves a Crackmes.one user profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching crackmes profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, urlStr, username, c.logger)
}

func parseProfile(htmlBytes []byte, url, username string, logger *slog.Logger) (*profile.Profile, error) {
	htmlStr := string(htmlBytes)

	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Parse HTML for structured extraction
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		logger.Warn("failed to parse HTML", "error", err)
	}

	// Extract title - usually shows "{username}'s profile"
	title := htmlutil.Title(htmlStr)
	if title != "" {
		// Remove suffixes
		title = strings.TrimSuffix(title, " - Crackmes.one")
		title = strings.TrimSuffix(title, "'s profile")
		title = strings.TrimSuffix(title, " profile")
		prof.DisplayName = strings.TrimSpace(title)
	}

	// Extract stats from page
	if doc != nil {
		extractStats(doc, prof, logger)
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(htmlStr)

	// Filter out Crackmes.one's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "crackmes.one") {
			filtered = append(filtered, link)
		}
	}
	prof.SocialLinks = filtered

	// Use username as fallback for display name
	if prof.DisplayName == "" {
		prof.DisplayName = username
	}

	return prof, nil
}

func extractStats(doc *html.Node, prof *profile.Profile, logger *slog.Logger) {
	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.TextNode {
			text := strings.TrimSpace(n.Data)

			// Look for stat patterns like "Crackmes submitted: 2"
			if strings.Contains(text, "submitted:") {
				parts := strings.Split(text, ":")
				if len(parts) == 2 {
					prof.Fields["crackmes_submitted"] = strings.TrimSpace(parts[1])
				}
			} else if strings.Contains(text, "Writeups:") || strings.Contains(text, "Writeups authored:") {
				parts := strings.Split(text, ":")
				if len(parts) == 2 {
					prof.Fields["writeups"] = strings.TrimSpace(parts[1])
				}
			} else if strings.Contains(text, "Comments:") || strings.Contains(text, "Comments made:") {
				parts := strings.Split(text, ":")
				if len(parts) == 2 {
					prof.Fields["comments"] = strings.TrimSpace(parts[1])
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(doc)
}

func extractUsername(urlStr string) string {
	// Extract username from crackmes.one/user/{username} pattern
	if matches := usernamePattern.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}
	return ""
}
