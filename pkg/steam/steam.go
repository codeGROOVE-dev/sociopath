// Package steam fetches Steam user profile data.
package steam

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"

	"golang.org/x/net/html"
)

const platform = "steam"

// URL patterns for Steam profiles.
var (
	customURLPattern = regexp.MustCompile(`(?i)steamcommunity\.com/id/([a-zA-Z0-9_-]+)`)
	profileIDPattern = regexp.MustCompile(`(?i)steamcommunity\.com/profiles/(\d+)`)
)

// Match returns true if the URL is a Steam profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "steamcommunity.com/") {
		return false
	}
	return customURLPattern.MatchString(urlStr) || profileIDPattern.MatchString(urlStr)
}

// AuthRequired returns false because Steam public profiles don't require auth.
func AuthRequired() bool { return false }

// Client handles Steam requests.
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

// New creates a Steam client.
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

// Fetch retrieves a Steam profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching steam profile", "url", urlStr, "username", username)

	// Build the profile URL
	var profileURL string
	if profileIDPattern.MatchString(urlStr) {
		profileURL = fmt.Sprintf("https://steamcommunity.com/profiles/%s", username)
	} else {
		profileURL = fmt.Sprintf("https://steamcommunity.com/id/%s", username)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	// Check for error page
	if strings.Contains(string(body), "Steam Community :: Error") {
		return nil, profile.ErrProfileNotFound
	}

	return parseHTML(body, username, urlStr)
}

//nolint:gocognit,nestif // HTML parsing requires nested conditionals
func parseHTML(body []byte, username, url string) (*profile.Profile, error) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse steam HTML: %w", err)
	}

	//nolint:varnamelen // p is idiomatic for profile
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Extract persona name (display name)
			if n.Data == "span" && hasClass(n, "actual_persona_name") {
				if text := getTextContent(n); text != "" {
					p.Name = text
				}
			}

			// Extract real name from <bdi> inside header_real_name
			if n.Data == "bdi" && n.Parent != nil && hasClass(n.Parent, "header_real_name") {
				if text := strings.TrimSpace(getTextContent(n)); text != "" && text != p.Name {
					p.Fields["real_name"] = text
				}
			}

			// Extract detailed location from header_location div
			if n.Data == "div" && hasClass(n, "header_location") {
				if text := strings.TrimSpace(getTextContent(n)); text != "" {
					// Clean up whitespace and newlines
					text = strings.Join(strings.Fields(text), " ")
					if text != "" {
						p.Location = text
					}
				}
			}

			// Extract profile summary (bio)
			if n.Data == "div" && hasClass(n, "profile_summary") {
				if text := strings.TrimSpace(getTextContent(n)); text != "" {
					// Clean up the bio text
					text = strings.TrimPrefix(text, "No information given.")
					text = strings.TrimSpace(text)
					if text != "" && p.Bio == "" {
						p.Bio = text
					}
				}
			}

			// Extract avatar URL
			if n.Data == "img" && p.AvatarURL == "" {
				for _, attr := range n.Attr {
					if attr.Key == "src" && strings.Contains(attr.Val, "avatars") && strings.Contains(attr.Val, "_full") {
						p.AvatarURL = attr.Val
						break
					}
				}
			}

			// Extract country code from flag (fallback if no detailed location)
			if n.Data == "img" && hasClass(n, "profile_flag") && p.Location == "" {
				for _, attr := range n.Attr {
					if attr.Key == "src" {
						// Extract country code from flag URL (e.g., us.gif -> US)
						if idx := strings.LastIndex(attr.Val, "/"); idx != -1 {
							filename := attr.Val[idx+1:]
							if countryCode, found := strings.CutSuffix(filename, ".gif"); found {
								p.Location = strings.ToUpper(countryCode)
							}
						}
						break
					}
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

	return p, nil
}

func hasClass(n *html.Node, class string) bool {
	for _, attr := range n.Attr {
		if attr.Key == "class" {
			return slices.Contains(strings.Fields(attr.Val), class)
		}
	}
	return false
}

func getTextContent(n *html.Node) string {
	var sb strings.Builder
	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.TextNode {
			sb.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(n)
	return strings.TrimSpace(sb.String())
}

func extractUsername(urlStr string) string {
	if matches := customURLPattern.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}
	if matches := profileIDPattern.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}
	return ""
}
