// Package jianshu fetches Jianshu (简书) user profile data.
package jianshu

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

const platform = "jianshu"

// platformInfo implements profile.Platform for Jianshu.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var userIDPattern = regexp.MustCompile(`(?i)jianshu\.com/u/([a-zA-Z0-9]+)`)

// Match returns true if the URL is a Jianshu profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "jianshu.com/") {
		return false
	}
	return userIDPattern.MatchString(urlStr)
}

// AuthRequired returns false because Jianshu profiles are public.
func AuthRequired() bool { return false }

// Client handles Jianshu requests.
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

// New creates a Jianshu client.
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

// Fetch retrieves a Jianshu profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	userID := extractUserID(urlStr)
	if userID == "" {
		return nil, fmt.Errorf("could not extract user ID from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching jianshu profile", "url", urlStr, "user_id", userID)

	profileURL := fmt.Sprintf("https://www.jianshu.com/u/%s", userID)

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
		return nil, fmt.Errorf("failed to parse jianshu HTML: %w", err)
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: userID,
		Fields:   make(map[string]string),
		Badges:   make(map[string]string),
	}

	var posts []profile.Post
	var socialLinks []string

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Extract from title tag
			if n.Data == "title" && n.FirstChild != nil {
				title := strings.TrimSpace(n.FirstChild.Data)
				if strings.Contains(title, " - 简书") {
					parts := strings.Split(title, " - 简书")
					if len(parts) > 0 && parts[0] != "" {
						p.DisplayName = strings.TrimSpace(parts[0])
					}
				}
			}

			// Extract meta description for bio
			if n.Data == "meta" {
				var name, content, property string
				for _, attr := range n.Attr {
					switch attr.Key {
					case "name":
						name = attr.Val
					case "property":
						property = attr.Val
					case "content":
						content = attr.Val
					}
				}
				if (name == "description" || property == "og:description") && content != "" && p.Bio == "" {
					p.Bio = strings.TrimSpace(content)
				}
			}

			// Extract avatar URL
			if p.AvatarURL == "" {
				if hasClass(n, "avatar") {
					if img := findElement(n, "img"); img != nil {
						if src := getAttribute(img, "src"); src != "" {
							p.AvatarURL = src
						}
					}
				}
			}

			// Extract user info
			if hasClass(n, "info") {
				extractInfo(n, p)
			}

			// Extract statistics
			if hasClass(n, "meta-block") {
				extractStats(n, p)
			}

			// Extract articles
			if hasClass(n, "note-list") || hasClass(n, "article") {
				if post := extractPost(n); post.Title != "" {
					posts = append(posts, post)
				}
			}

			// Extract social links
			if hasClass(n, "social-link") {
				if a := findElement(n, "a"); a != nil {
					if href := getAttribute(a, "href"); href != "" && !strings.Contains(href, "jianshu.com") {
						socialLinks = append(socialLinks, href)
					}
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
		p.DisplayName = userID
	}

	// Check for not found
	//nolint:gosmopolitan // Chinese text for error detection
	if strings.Contains(string(body), "404") || strings.Contains(string(body), "用户不存在") {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func extractInfo(n *html.Node, p *profile.Profile) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			if hasClass(c, "title") && p.DisplayName == "" {
				p.DisplayName = strings.TrimSpace(getTextContent(c))
			}
			if hasClass(c, "signature") && p.Bio == "" {
				p.Bio = strings.TrimSpace(getTextContent(c))
			}
		}
	}
}

func extractStats(n *html.Node, p *profile.Profile) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			if hasClass(c, "followers-count") {
				p.Fields["followers"] = strings.TrimSpace(getTextContent(c))
			}
			if hasClass(c, "following-count") {
				p.Fields["following"] = strings.TrimSpace(getTextContent(c))
			}
			if hasClass(c, "articles-count") {
				p.Fields["articles"] = strings.TrimSpace(getTextContent(c))
			}
			if hasClass(c, "wordage") {
				p.Fields["total_wordage"] = strings.TrimSpace(getTextContent(c))
			}
			if hasClass(c, "likes-count") {
				p.Fields["likes"] = strings.TrimSpace(getTextContent(c))
			}
		}
	}
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
						if !strings.HasPrefix(href, "http") {
							href = "https://www.jianshu.com" + href
						}
						post.URL = href
					}
				}
			}

			if hasClass(node, "abstract") {
				if text := getTextContent(node); text != "" {
					post.Content = strings.TrimSpace(text)
				}
			}

			if hasClass(node, "date") || hasClass(node, "time") {
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

func extractUserID(urlStr string) string {
	matches := userIDPattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
