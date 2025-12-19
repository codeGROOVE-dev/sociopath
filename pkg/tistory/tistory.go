// Package tistory fetches Tistory (Korean blog platform) user profile data.
package tistory

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

const platform = "tistory"

// platformInfo implements profile.Platform for Tistory.
type platformInfo struct{}

func (platformInfo) Name() string {
	return platform
}

func (platformInfo) Type() profile.PlatformType {
	return profile.PlatformTypeBlog
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

var usernamePattern = regexp.MustCompile(`(?i)([a-zA-Z0-9_-]+)\.tistory\.com`)

// Match returns true if the URL is a Tistory blog URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, ".tistory.com") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Tistory profiles are public.
func AuthRequired() bool { return false }

// Client handles Tistory requests.
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

// New creates a Tistory client.
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

// Fetch retrieves a Tistory blog profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	// Normalize URL to main blog page
	normalizedURL := fmt.Sprintf("https://%s.tistory.com", username)
	c.logger.InfoContext(ctx, "fetching tistory profile", "url", normalizedURL, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
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
		// Continue with string-based extraction
	}

	// Extract blog title/author name from title tag
	title := htmlutil.Title(htmlStr)
	if title != "" {
		prof.DisplayName = strings.TrimSpace(title)
	}

	// Extract bio/description from meta description
	prof.Bio = htmlutil.Description(htmlStr)

	// Extract avatar from blog image (look for common Tistory patterns)
	if doc != nil {
		var extractAvatar func(*html.Node)
		extractAvatar = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "img" {
				alt := getAttribute(n, "alt")
				src := getAttribute(n, "src")
				// Look for blog images
				if (strings.Contains(alt, "블로그 이미지") || strings.Contains(alt, "프로필") ||
					strings.Contains(alt, "profile")) && src != "" && prof.AvatarURL == "" {
					prof.AvatarURL = src
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractAvatar(c)
			}
		}
		extractAvatar(doc)
	}

	// Extract recent posts (limit to 10)
	if doc != nil {
		posts := extractPosts(doc, logger)
		if len(posts) > 10 {
			posts = posts[:10]
		}
		prof.Posts = posts
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(htmlStr)

	// Filter out Tistory's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "tistory.com") {
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

func extractPosts(doc *html.Node, logger *slog.Logger) []profile.Post {
	var posts []profile.Post

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		// Look for article elements or post listings
		if n.Type == html.ElementNode {
			class := getAttribute(n, "class")

			// Common Tistory post listing patterns
			isPostElement := strings.Contains(class, "article") ||
				strings.Contains(class, "post") ||
				strings.Contains(class, "entry") ||
				strings.Contains(class, "item")

			if isPostElement {
				post := extractPostFromElement(n)
				if post.Title != "" || post.Content != "" {
					posts = append(posts, post)
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(doc)

	return posts
}

func extractPostFromElement(n *html.Node) profile.Post {
	post := profile.Post{Type: profile.PostTypeArticle}

	var extractData func(*html.Node)
	extractData = func(node *html.Node) {
		if node.Type == html.ElementNode {
			class := getAttribute(node, "class")

			// Extract title
			if (node.Data == "h2" || node.Data == "h3" || node.Data == "h4" ||
				strings.Contains(class, "title") || strings.Contains(class, "subject")) &&
				post.Title == "" {
				title := getTextContent(node)
				if title != "" {
					post.Title = strings.TrimSpace(title)
				}
			}

			// Extract link
			if node.Data == "a" && post.URL == "" && post.Title != "" {
				href := getAttribute(node, "href")
				if href != "" && !strings.HasPrefix(href, "#") {
					post.URL = href
				}
			}

			// Extract content/excerpt
			if (strings.Contains(class, "excerpt") || strings.Contains(class, "summary") ||
				strings.Contains(class, "desc") || strings.Contains(class, "content")) &&
				post.Content == "" {
				content := getTextContent(node)
				if content != "" && len(content) > 10 {
					post.Content = strings.TrimSpace(content)
					if len(post.Content) > 200 {
						post.Content = post.Content[:200] + "..."
					}
				}
			}

			// Extract date
			if (strings.Contains(class, "date") || strings.Contains(class, "time") ||
				node.Data == "time") && post.Date == "" {
				date := getTextContent(node)
				if date != "" {
					post.Date = strings.TrimSpace(date)
				}
			}
		}

		for c := node.FirstChild; c != nil; c = c.NextSibling {
			extractData(c)
		}
	}
	extractData(n)

	return post
}

func getAttribute(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

func getTextContent(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var text strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		text.WriteString(getTextContent(c))
	}
	return text.String()
}

func extractUsername(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")

	// Extract username.tistory.com pattern
	if matches := usernamePattern.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
