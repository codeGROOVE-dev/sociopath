// Package zerosec fetches 0x00sec (security research forum) user profile data.
package zerosec

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

const platform = "0x00sec"

// platformInfo implements profile.Platform for 0x00sec.
type platformInfo struct{}

func (platformInfo) Name() string {
	return platform
}

func (platformInfo) Type() profile.PlatformType {
	return profile.PlatformTypeForum
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

// Match patterns for both main site and archive
var usernamePattern = regexp.MustCompile(`(?i)(?:archive\.)?0x00sec\.org/u(?:sers)?/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a 0x00sec user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return (strings.Contains(lower, "0x00sec.org/u/") ||
		strings.Contains(lower, "0x00sec.org/users/")) &&
		usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because 0x00sec profiles are public.
func AuthRequired() bool { return false }

// Client handles 0x00sec requests.
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

// New creates a 0x00sec client.
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

// Fetch retrieves a 0x00sec user profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching 0x00sec profile", "url", urlStr, "username", username)

	// Try archive site first (more stable)
	archiveURL := fmt.Sprintf("https://archive.0x00sec.org/u/%s", username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, archiveURL, username, c.logger)
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

	// Extract title
	title := htmlutil.Title(htmlStr)
	if title != "" {
		// Remove site suffix if present
		title = strings.TrimSuffix(title, " - 0x00sec - The Home of the Hacker")
		prof.DisplayName = strings.TrimSpace(title)
	}

	// Extract bio from about section
	bioPattern := regexp.MustCompile(`<div[^>]*class="[^"]*bio[^"]*"[^>]*>([^<]+)</div>`)
	if m := bioPattern.FindStringSubmatch(htmlStr); len(m) > 1 {
		prof.Bio = strings.TrimSpace(m[1])
	}

	// Extract avatar URL
	avatarPattern := regexp.MustCompile(`<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(htmlStr); len(m) > 1 {
		avatarURL := m[1]
		// Make relative URLs absolute
		if strings.HasPrefix(avatarURL, "//") {
			avatarURL = "https:" + avatarURL
		} else if strings.HasPrefix(avatarURL, "/") {
			avatarURL = "https://archive.0x00sec.org" + avatarURL
		} else if strings.HasPrefix(avatarURL, "../") {
			avatarURL = "https://archive.0x00sec.org/" + strings.TrimPrefix(avatarURL, "../")
		}
		prof.AvatarURL = avatarURL
	}

	// Extract stats if available
	if doc != nil {
		extractStats(doc, prof, logger)
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(htmlStr)

	// Filter out 0x00sec's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "0x00sec.org") {
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
		if n.Type == html.ElementNode {
			// Look for Discourse stat elements
			if n.Data == "dd" || n.Data == "span" {
				// Check if this is a stats element
				text := getTextContent(n)
				text = strings.TrimSpace(text)

				// Try to identify stats by nearby labels
				if prev := n.PrevSibling; prev != nil {
					label := strings.ToLower(getTextContent(prev))
					if strings.Contains(label, "post") {
						prof.Fields["posts"] = text
					} else if strings.Contains(label, "topic") {
						prof.Fields["topics"] = text
					} else if strings.Contains(label, "like") {
						prof.Fields["likes"] = text
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(doc)
}

func getTextContent(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var result strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		result.WriteString(getTextContent(c))
	}
	return result.String()
}

func extractUsername(urlStr string) string {
	if matches := usernamePattern.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}
	return ""
}
