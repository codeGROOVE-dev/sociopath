// Package cto51 fetches 51CTO user profile data.
package cto51

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

const platform = "51cto"

// platformInfo implements profile.Platform for 51CTO.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)blog\.51cto\.com/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a 51CTO profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "51cto.com/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because 51CTO profiles are public.
func AuthRequired() bool { return false }

// Client handles 51CTO requests.
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

// New creates a 51CTO client.
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

// Fetch retrieves a 51CTO profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching 51cto profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://blog.51cto.com/%s", username)

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
		return nil, fmt.Errorf("failed to parse 51cto HTML: %w", err)
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	var posts []profile.Post

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if n.Data == "title" && n.FirstChild != nil {
				title := strings.TrimSpace(n.FirstChild.Data)
				if strings.Contains(title, " - 51CTO") {
					parts := strings.Split(title, " - 51CTO")
					if len(parts) > 0 {
						p.DisplayName = strings.TrimSpace(parts[0])
					}
				}
			}

			if n.Data == "meta" {
				var name, content string
				for _, attr := range n.Attr {
					if attr.Key == "name" {
						name = attr.Val
					} else if attr.Key == "content" {
						content = attr.Val
					}
				}
				if name == "description" && content != "" && p.Bio == "" {
					p.Bio = strings.TrimSpace(content)
				}
			}

			if p.AvatarURL == "" && (hasClass(n, "avatar") || hasClass(n, "user-avatar")) {
				if img := findElement(n, "img"); img != nil {
					if src := getAttribute(img, "src"); src != "" {
						p.AvatarURL = src
					}
				}
			}

			if hasClass(n, "article") || hasClass(n, "post") {
				if post := extractPost(n); post.Title != "" {
					posts = append(posts, post)
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(doc)

	if len(posts) > 0 {
		p.Posts = posts
	}

	if p.DisplayName == "" {
		p.DisplayName = username
	}

	//nolint:gosmopolitan // Chinese text for error detection
	if strings.Contains(string(body), "404") || strings.Contains(string(body), "博客不存在") {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func extractPost(n *html.Node) profile.Post {
	post := profile.Post{Type: profile.PostTypeArticle}

	var extract func(*html.Node)
	extract = func(node *html.Node) {
		if node.Type == html.ElementNode {
			if hasClass(node, "title") {
				if a := findElement(node, "a"); a != nil {
					post.Title = strings.TrimSpace(getTextContent(a))
					if href := getAttribute(a, "href"); href != "" {
						post.URL = href
					}
				}
			}

			if hasClass(node, "summary") || hasClass(node, "abstract") {
				post.Content = strings.TrimSpace(getTextContent(node))
			}
		}

		for c := node.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(n)
	return post
}

func hasClass(n *html.Node, className string) bool {
	for _, attr := range n.Attr {
		if attr.Key == "class" && strings.Contains(attr.Val, className) {
			return true
		}
	}
	return false
}

func getAttribute(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

func findElement(n *html.Node, tagName string) *html.Node {
	if n.Type == html.ElementNode && n.Data == tagName {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if result := findElement(c, tagName); result != nil {
			return result
		}
	}
	return nil
}

func getTextContent(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var builder strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		builder.WriteString(getTextContent(c))
	}
	return builder.String()
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
