// Package csdn fetches CSDN blog user profile data.
package csdn

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

const platform = "csdn"

var usernamePattern = regexp.MustCompile(`(?i)blog\.csdn\.net/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a CSDN blog profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "csdn.net/") {
		return false
	}
	// Exclude article URLs
	if strings.Contains(lower, "/article/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because CSDN profiles are public.
func AuthRequired() bool { return false }

// Client handles CSDN requests.
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

// New creates a CSDN client.
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

// Fetch retrieves a CSDN profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching csdn profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://blog.csdn.net/%s", username)

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

//nolint:gosmopolitan // Chinese text for error detection
func parseHTML(body []byte, username, url string) (*profile.Profile, error) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse csdn HTML: %w", err)
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
			// Extract from title tag: "用户名-CSDN博客"
			if n.Data == "title" && n.FirstChild != nil {
				title := strings.TrimSpace(n.FirstChild.Data)
				if strings.Contains(title, "-CSDN") {
					parts := strings.Split(title, "-CSDN")
					if len(parts) > 0 && parts[0] != "" {
						p.Name = strings.TrimSpace(parts[0])
					}
				}
			}

			// Extract meta description for bio
			if n.Data == "meta" {
				var name, content string
				for _, attr := range n.Attr {
					switch attr.Key {
					case "name":
						name = attr.Val
					case "content":
						content = attr.Val
					default:
						// Ignore other attributes
					}
				}
				if name == "description" && content != "" && p.Bio == "" {
					p.Bio = strings.TrimSpace(content)
				}
				if name == "keywords" && content != "" {
					p.Fields["keywords"] = content
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
	if strings.Contains(string(body), "404") || strings.Contains(string(body), "用户不存在") {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
