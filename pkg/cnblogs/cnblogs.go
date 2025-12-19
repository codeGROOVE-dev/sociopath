// Package cnblogs fetches CNBlogs (博客园) user profile data.
package cnblogs

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

const platform = "cnblogs"

// platformInfo implements profile.Platform for CNBlogs.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)cnblogs\.com/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a CNBlogs profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "cnblogs.com/") {
		return false
	}
	// Exclude post URLs
	if strings.Contains(lower, "/p/") || strings.Contains(lower, "/archive/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because CNBlogs profiles are public.
func AuthRequired() bool { return false }

// Client handles CNBlogs requests.
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

// New creates a CNBlogs client.
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

// Fetch retrieves a CNBlogs profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching cnblogs profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://www.cnblogs.com/%s", username)

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
		return nil, fmt.Errorf("failed to parse cnblogs HTML: %w", err)
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
			// Extract from title
			if n.Data == "title" && n.FirstChild != nil {
				title := strings.TrimSpace(n.FirstChild.Data)
				if strings.Contains(title, " - 博客园") {
					parts := strings.Split(title, " - 博客园")
					if len(parts) > 0 {
						p.DisplayName = strings.TrimSpace(parts[0])
					}
				}
			}

			// Extract meta description
			if n.Data == "meta" {
				var name, content string
				for _, attr := range n.Attr {
					switch attr.Key {
					case "name":
						name = attr.Val
					case "content":
						content = attr.Val
					}
				}
				if name == "description" && content != "" && p.Bio == "" {
					p.Bio = strings.TrimSpace(content)
				}
			}

			// Extract avatar
			if p.AvatarURL == "" && (hasClass(n, "avatar") || getAttribute(n, "id") == "profile_block") {
				if img := findElement(n, "img"); img != nil {
					if src := getAttribute(img, "src"); src != "" {
						p.AvatarURL = src
					}
				}
			}

			// Extract posts
			if hasClass(n, "post-item") || hasClass(n, "postTitle") {
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
	if strings.Contains(string(body), "404") || strings.Contains(string(body), "找不到") {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func extractPost(n *html.Node) profile.Post {
	post := profile.Post{Type: profile.PostTypeArticle}

	var extract func(*html.Node)
	extract = func(node *html.Node) {
		if node.Type == html.ElementNode {
			if node.Data == "a" && post.Title == "" {
				post.Title = strings.TrimSpace(getTextContent(node))
				if href := getAttribute(node, "href"); href != "" {
					post.URL = href
				}
			}

			if hasClass(node, "postDesc") || hasClass(node, "c_b_p_desc") {
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

// Helper functions.

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
