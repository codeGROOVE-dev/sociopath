// Package cnode fetches CNode (Node.js中文社区) user profile data.
package cnode

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

const platform = "cnode"

// platformInfo implements profile.Platform for CNode.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)cnodejs\.org/user/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a CNode profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "cnodejs.org/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because CNode profiles are public.
func AuthRequired() bool { return false }

// Client handles CNode requests.
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

// New creates a CNode client.
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

// Fetch retrieves a CNode profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching cnode profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://cnodejs.org/user/%s", username)

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
		return nil, fmt.Errorf("failed to parse cnode HTML: %w", err)
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	var posts []profile.Post
	var socialLinks []string

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Extract from title tag
			if n.Data == "title" && n.FirstChild != nil {
				title := strings.TrimSpace(n.FirstChild.Data)
				if strings.Contains(title, " - CNode技术社区") {
					parts := strings.Split(title, " - CNode技术社区")
					if len(parts) > 0 && parts[0] != "" {
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
			if p.AvatarURL == "" {
				if hasClass(n, "user-avatar") || hasClass(n, "avatar") {
					if img := findElement(n, "img"); img != nil {
						if src := getAttribute(img, "src"); src != "" {
							p.AvatarURL = src
						}
					}
				}
			}

			// Extract user info
			if hasClass(n, "user-info") || hasClass(n, "user_big_info") {
				extractUserInfo(n, p, &socialLinks)
			}

			// Extract statistics
			if hasClass(n, "user-profile") {
				extractStats(n, p)
			}

			// Extract topics/posts
			if hasClass(n, "topic-item") || hasClass(n, "cell") {
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

	// Add collected data
	if len(posts) > 0 {
		p.Posts = posts
	}
	if len(socialLinks) > 0 {
		p.SocialLinks = uniqueStrings(socialLinks)
	}

	// Default name if not found
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	// Check for not found
	//nolint:gosmopolitan // Chinese text for error detection
	if strings.Contains(string(body), "404") || strings.Contains(string(body), "找不到") {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func extractUserInfo(n *html.Node, p *profile.Profile, socialLinks *[]string) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			if hasClass(c, "user-name") && p.DisplayName == "" {
				p.DisplayName = strings.TrimSpace(getTextContent(c))
			}
			if hasClass(c, "user-location") {
				p.Fields["location"] = strings.TrimSpace(getTextContent(c))
			}
			if hasClass(c, "user-website") || hasClass(c, "dark-btn") {
				if a := findElement(c, "a"); a != nil {
					if href := getAttribute(a, "href"); href != "" && !strings.Contains(href, "cnodejs.org") {
						*socialLinks = append(*socialLinks, href)
					}
				}
			}
			if hasClass(c, "user-signature") && p.Bio == "" {
				p.Bio = strings.TrimSpace(getTextContent(c))
			}
		}
	}
}

func extractStats(n *html.Node, p *profile.Profile) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			text := strings.TrimSpace(getTextContent(c))
			//nolint:gosmopolitan // Chinese text required
			if strings.Contains(text, "注册时间") {
				parts := strings.Split(text, "：")
				if len(parts) > 1 {
					p.Fields["join_date"] = strings.TrimSpace(parts[1])
				}
			}
			//nolint:gosmopolitan // Chinese text required
			if strings.Contains(text, "积分") {
				parts := strings.Split(text, "：")
				if len(parts) > 1 {
					p.Fields["score"] = strings.TrimSpace(parts[1])
				}
			}
		}
	}
}

func extractPost(n *html.Node) profile.Post {
	post := profile.Post{Type: profile.PostTypePost}

	var extract func(*html.Node)
	extract = func(node *html.Node) {
		if node.Type == html.ElementNode {
			if hasClass(node, "topic-title") || hasClass(node, "title") {
				if a := findElement(node, "a"); a != nil {
					post.Title = strings.TrimSpace(getTextContent(a))
					if href := getAttribute(a, "href"); href != "" {
						if !strings.HasPrefix(href, "http") {
							href = "https://cnodejs.org" + href
						}
						post.URL = href
					}
				}
			}

			if hasClass(node, "last-active-time") || hasClass(node, "date") {
				if text := getTextContent(node); text != "" {
					post.Date = strings.TrimSpace(text)
				}
			}
		}

		for c := node.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(n)
	return post
}

// Helper functions for HTML parsing.

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

func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range slice {
		if !seen[s] && s != "" {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
