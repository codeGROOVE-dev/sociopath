// Package sessionize fetches Sessionize speaker profile data.
package sessionize

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"

	"golang.org/x/net/html"
)

const platform = "sessionize"

var usernamePattern = regexp.MustCompile(`(?i)sessionize\.com/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Sessionize speaker profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "sessionize.com/") {
		return false
	}
	// Exclude non-profile paths
	excluded := []string{"/playbook", "/features", "/speakers", "/api", "/app/"}
	for _, ex := range excluded {
		if strings.Contains(lower, ex) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Sessionize speaker profiles are public.
func AuthRequired() bool { return false }

// Client handles Sessionize requests.
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

// New creates a Sessionize client.
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

// Fetch retrieves a Sessionize speaker profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching sessionize profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://sessionize.com/%s/", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(body, username, urlStr)
}

//nolint:gocognit,nestif,varnamelen // HTML parsing requires nested conditionals
func parseHTML(body []byte, username, url string) (*profile.Profile, error) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse sessionize HTML: %w", err)
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Extract from title tag: "Name's Speaker Profile @ Sessionize"
			if n.Data == "title" && n.FirstChild != nil {
				title := strings.TrimSpace(n.FirstChild.Data)
				if strings.Contains(title, "Speaker Profile") {
					// Format: "Name's Speaker Profile @ Sessionize"
					if idx := strings.Index(title, "'s Speaker Profile"); idx > 0 {
						p.Name = strings.TrimSpace(title[:idx])
					} else if idx := strings.Index(title, " Speaker Profile"); idx > 0 {
						p.Name = strings.TrimSpace(title[:idx])
					}
				}
			}

			// Extract meta description for bio
			if n.Data == "meta" {
				var name, property, content string
				for _, attr := range n.Attr {
					switch attr.Key {
					case "name":
						name = attr.Val
					case "property":
						property = attr.Val
					case "content":
						content = attr.Val
					default:
						// Ignore other attributes
					}
				}
				if name == "description" && content != "" && p.Bio == "" {
					p.Bio = strings.TrimSpace(content)
				}
				if property == "og:image" && content != "" && p.AvatarURL == "" {
					p.AvatarURL = content
				}
			}

			// Extract social links from anchor tags
			if n.Data == "a" {
				var href string
				for _, attr := range n.Attr {
					if attr.Key == "href" {
						href = attr.Val
						break
					}
				}
				if href != "" && isSocialLink(href) {
					p.SocialLinks = append(p.SocialLinks, href)
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(doc)

	// Default name if not found
	if p.Name == "" {
		p.Name = username
	}

	// Check for not found
	if strings.Contains(string(body), "<h1>404</h1>") || strings.Contains(string(body), "Page Not Found") {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func isSocialLink(href string) bool {
	socialDomains := []string{
		"twitter.com", "x.com", "linkedin.com", "github.com",
		"facebook.com", "instagram.com", "youtube.com", "mastodon",
	}
	lower := strings.ToLower(href)
	for _, domain := range socialDomains {
		if strings.Contains(lower, domain) {
			return true
		}
	}
	return false
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
