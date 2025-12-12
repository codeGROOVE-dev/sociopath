// Package juejin fetches Juejin (掘金) user profile data.
package juejin

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

const platform = "juejin"

var userIDPattern = regexp.MustCompile(`(?i)juejin\.cn/user/(\d+)`)

// Match returns true if the URL is a Juejin profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "juejin.cn/") {
		return false
	}
	return userIDPattern.MatchString(urlStr)
}

// AuthRequired returns false because Juejin profiles are public.
func AuthRequired() bool { return false }

// Client handles Juejin requests.
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

// New creates a Juejin client.
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

// Fetch retrieves a Juejin profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	userID := extractUserID(urlStr)
	if userID == "" {
		return nil, fmt.Errorf("could not extract user ID from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching juejin profile", "url", urlStr, "user_id", userID)

	profileURL := fmt.Sprintf("https://juejin.cn/user/%s", userID)

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

	return parseHTML(body, userID, urlStr)
}

//nolint:gosmopolitan // Chinese text for error detection
func parseHTML(body []byte, userID, url string) (*profile.Profile, error) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse juejin HTML: %w", err)
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: userID,
		Fields:   make(map[string]string),
	}

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Extract from title tag: "用户名 的个人主页 - 动态 - 掘金"
			if n.Data == "title" && n.FirstChild != nil {
				title := strings.TrimSpace(n.FirstChild.Data)
				if strings.Contains(title, "的个人主页") {
					parts := strings.Split(title, " 的个人主页")
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
		p.Name = userID
	}

	// Check for not found
	if strings.Contains(string(body), "页面不存在") || strings.Contains(string(body), "用户不存在") {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func extractUserID(urlStr string) string {
	matches := userIDPattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
