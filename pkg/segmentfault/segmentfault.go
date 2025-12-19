// Package segmentfault fetches SegmentFault user profile data.
package segmentfault

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

const platform = "segmentfault"

// platformInfo implements profile.Platform for SegmentFault.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)segmentfault\.com/u/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a SegmentFault profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "segmentfault.com/") {
		return false
	}
	// Exclude article/question URLs
	if strings.Contains(lower, "/a/") || strings.Contains(lower, "/q/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because SegmentFault profiles are public.
func AuthRequired() bool { return false }

// Client handles SegmentFault requests.
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

// New creates a SegmentFault client.
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

// Fetch retrieves a SegmentFault profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching segmentfault profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://segmentfault.com/u/%s", username)

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
		return nil, fmt.Errorf("failed to parse segmentfault HTML: %w", err)
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
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
				if strings.Contains(title, " - SegmentFault") {
					parts := strings.Split(title, " - SegmentFault")
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
				if hasClass(n, "avatar") || hasClass(n, "user-avatar") {
					if img := findElement(n, "img"); img != nil {
						if src := getAttribute(img, "src"); src != "" {
							p.AvatarURL = src
						}
					}
				}
			}

			// Extract location
			if hasClass(n, "location") || hasClass(n, "user-location") {
				if text := getTextContent(n); text != "" {
					p.Fields["location"] = strings.TrimSpace(text)
				}
			}

			// Extract company/organization
			if hasClass(n, "company") || hasClass(n, "user-company") {
				if text := getTextContent(n); text != "" {
					p.Fields["company"] = strings.TrimSpace(text)
				}
			}

			// Extract website
			if hasClass(n, "website") || hasClass(n, "user-website") {
				if a := findElement(n, "a"); a != nil {
					if href := getAttribute(a, "href"); href != "" {
						p.Fields["website"] = href
						socialLinks = append(socialLinks, href)
					}
				}
			}

			// Extract statistics
			if hasClass(n, "stats") || hasClass(n, "user-stats") {
				extractStats(n, p)
			}

			// Extract badges/reputation
			if hasClass(n, "badge") || hasClass(n, "reputation") {
				if text := getTextContent(n); text != "" {
					p.Badges["reputation"] = strings.TrimSpace(text)
				}
			}

			// Extract articles/posts
			if hasClass(n, "article-item") || hasClass(n, "blog-item") {
				if post := extractPost(n); post.Title != "" {
					posts = append(posts, post)
				}
			}

			// Extract social links
			if hasClass(n, "social-link") || hasClass(n, "user-social") {
				if a := findElement(n, "a"); a != nil {
					if href := getAttribute(a, "href"); href != "" && !strings.Contains(href, "segmentfault.com") {
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
		p.DisplayName = username
	}

	// Check for not found
	//nolint:gosmopolitan // Chinese text for error detection
	if strings.Contains(string(body), "404") || strings.Contains(string(body), "用户不存在") {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func extractStats(n *html.Node, p *profile.Profile) {
	var statName, statValue string
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			if hasClass(c, "stat-name") || hasClass(c, "label") {
				statName = strings.TrimSpace(getTextContent(c))
			}
			if hasClass(c, "stat-value") || hasClass(c, "count") {
				statValue = strings.TrimSpace(getTextContent(c))
			}
		}
	}

	if statName != "" && statValue != "" {
		key := strings.ToLower(strings.ReplaceAll(statName, " ", "_"))
		p.Fields[key] = statValue
	}
}

func extractPost(n *html.Node) profile.Post {
	post := profile.Post{Type: profile.PostTypeArticle}

	var extract func(*html.Node)
	extract = func(node *html.Node) {
		if node.Type == html.ElementNode {
			// Extract title and URL
			if hasClass(node, "title") || node.Data == "h3" || node.Data == "h4" {
				if a := findElement(node, "a"); a != nil {
					post.Title = strings.TrimSpace(getTextContent(a))
					if href := getAttribute(a, "href"); href != "" {
						if !strings.HasPrefix(href, "http") {
							href = "https://segmentfault.com" + href
						}
						post.URL = href
					}
				}
			}

			// Extract content/excerpt
			if hasClass(node, "excerpt") || hasClass(node, "summary") {
				if text := getTextContent(node); text != "" {
					post.Content = strings.TrimSpace(text)
				}
			}

			// Extract date
			if hasClass(node, "date") || hasClass(node, "time") {
				if text := getTextContent(node); text != "" {
					post.Date = strings.TrimSpace(text)
				}
			}

			// Extract tags/categories
			if hasClass(node, "tag") || hasClass(node, "category") {
				if text := getTextContent(node); text != "" {
					if post.Category == "" {
						post.Category = strings.TrimSpace(text)
					} else {
						post.Category += ", " + strings.TrimSpace(text)
					}
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
