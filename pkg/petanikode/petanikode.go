// Package petanikode fetches Petani Kode author profile data.
// Petani Kode is a popular Indonesian coding tutorial site.
package petanikode

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

const platform = "petanikode"

// platformInfo implements profile.Platform for Petani Kode.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)petanikode\.com/authors?/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Petani Kode author profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "petanikode.com/") {
		return false
	}
	// Match only author profile URLs
	return strings.Contains(lower, "/author") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Petani Kode profiles are public.
func AuthRequired() bool { return false }

// Client handles Petani Kode requests.
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

// New creates a Petani Kode client.
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

// Fetch retrieves a Petani Kode author profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching petanikode profile", "url", urlStr, "username", username)

	// Normalize URL (use /authors/ format)
	profileURL := fmt.Sprintf("https://www.petanikode.com/authors/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "id,en-US;q=0.7,en;q=0.3")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	p, err := parseHTML(body, username, profileURL)
	if err != nil {
		return nil, err
	}

	c.logger.InfoContext(ctx, "parsed petanikode profile",
		"display_name", p.DisplayName,
		"avatar_url", p.AvatarURL,
		"bio", p.Bio,
		"fields_count", len(p.Fields),
		"posts_count", len(p.Posts),
		"social_links_count", len(p.SocialLinks))

	return p, nil
}

//nolint:gosmopolitan // Indonesian text for error detection
func parseHTML(body []byte, username, url string) (*profile.Profile, error) {
	bodyStr := string(body)

	// Check for not found
	//nolint:gosmopolitan // Indonesian text for error detection
	if strings.Contains(bodyStr, "404") ||
		strings.Contains(bodyStr, "Not Found") ||
		strings.Contains(bodyStr, "Halaman tidak ditemukan") {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	doc, err := html.Parse(strings.NewReader(bodyStr))
	if err != nil {
		return nil, fmt.Errorf("failed to parse petanikode HTML: %w", err)
	}

	extractFromHTML(doc, p, bodyStr)

	// Default name if not found
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	return p, nil
}

// extractFromHTML extracts profile data from HTML.
func extractFromHTML(doc *html.Node, p *profile.Profile, bodyStr string) {
	var posts []profile.Post

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Extract from title tag
			if n.Data == "title" && n.FirstChild != nil {
				title := strings.TrimSpace(n.FirstChild.Data)
				if strings.Contains(title, " - Petanikode") {
					parts := strings.Split(title, " - Petanikode")
					if len(parts) > 0 && parts[0] != "" {
						p.DisplayName = strings.TrimSpace(parts[0])
					}
				}
			}

			// Extract meta tags for bio and avatar
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
				if property == "og:image" && content != "" && p.AvatarURL == "" {
					p.AvatarURL = content
				}
			}

			// Extract author bio/description
			if hasClass(n, "author-bio") || hasClass(n, "author-description") {
				if text := getTextContent(n); text != "" && len(text) > 10 {
					p.Bio = strings.TrimSpace(text)
				}
			}

			// Extract avatar
			if hasClass(n, "author-avatar") || hasClass(n, "author-image") {
				if n.Data == "img" {
					if src := getAttribute(n, "src"); src != "" {
						p.AvatarURL = src
					}
				}
			}

			// Extract article count
			if hasClass(n, "article-count") || hasClass(n, "post-count") {
				if text := extractNumber(getTextContent(n)); text != "" {
					p.Fields["article_count"] = text
				}
			}

			// Extract articles as posts
			if hasClass(n, "post") || hasClass(n, "article") {
				post := extractPost(n)
				if post.Title != "" {
					posts = append(posts, post)
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(doc)

	// Extract Open Graph data as fallback
	if p.DisplayName == "" {
		if name := htmlutil.ExtractMetaTag(bodyStr, "og:title"); name != "" {
			p.DisplayName = name
		}
	}
	if p.Bio == "" {
		if desc := htmlutil.ExtractMetaTag(bodyStr, "og:description"); desc != "" {
			p.Bio = desc
		}
	}
	if p.AvatarURL == "" {
		if img := htmlutil.OGImage(bodyStr); img != "" {
			p.AvatarURL = img
		}
	}

	// Extract social links from the page
	p.SocialLinks = extractSocialLinks(bodyStr)

	// Add posts
	if len(posts) > 0 {
		p.Posts = posts
	}
}

// extractPost extracts a blog post from a post node.
func extractPost(n *html.Node) profile.Post {
	post := profile.Post{Type: profile.PostTypeArticle}

	// Find title
	if titleNode := findElementWithClass(n, "post-title"); titleNode != nil {
		post.Title = strings.TrimSpace(getTextContent(titleNode))
	} else if titleNode := findElement(n, "h2"); titleNode != nil {
		post.Title = strings.TrimSpace(getTextContent(titleNode))
	} else if titleNode := findElement(n, "h3"); titleNode != nil {
		post.Title = strings.TrimSpace(getTextContent(titleNode))
	}

	// Find URL
	if link := findElement(n, "a"); link != nil {
		href := getAttribute(link, "href")
		if href != "" {
			if strings.HasPrefix(href, "/") {
				post.URL = "https://www.petanikode.com" + href
			} else if strings.HasPrefix(href, "http") {
				post.URL = href
			}
		}
	}

	// Find date
	if dateNode := findElementWithClass(n, "post-date"); dateNode != nil {
		dateStr := strings.TrimSpace(getTextContent(dateNode))
		if dateStr != "" {
			post.Date = dateStr
		}
	}

	return post
}

// extractSocialLinks finds social media links in the profile.
func extractSocialLinks(html string) []string {
	var links []string
	seen := make(map[string]bool)

	patterns := []struct {
		regex *regexp.Regexp
		base  string
	}{
		{regexp.MustCompile(`github\.com/([a-zA-Z0-9_-]+)`), "https://github.com/"},
		{regexp.MustCompile(`linkedin\.com/in/([a-zA-Z0-9_-]+)`), "https://linkedin.com/in/"},
		{regexp.MustCompile(`(?:twitter\.com|x\.com)/([a-zA-Z0-9_]+)`), "https://twitter.com/"},
		{regexp.MustCompile(`instagram\.com/([a-zA-Z0-9_.]+)`), "https://instagram.com/"},
		{regexp.MustCompile(`facebook\.com/([a-zA-Z0-9.]+)`), "https://facebook.com/"},
		{regexp.MustCompile(`t\.me/([a-zA-Z0-9_]+)`), "https://t.me/"},
	}

	for _, pat := range patterns {
		matches := pat.regex.FindAllStringSubmatch(html, -1)
		for _, m := range matches {
			if len(m) > 1 && m[1] != "share" && m[1] != "intent" {
				link := pat.base + m[1]
				if !seen[link] {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	// Also extract direct URLs from href attributes
	urlPattern := regexp.MustCompile(`href=["'](https?://(?:github|linkedin|twitter|instagram|facebook|t\.me)[^"']+)["']`)
	matches := urlPattern.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		if len(m) > 1 {
			link := m[1]
			if !seen[link] && !strings.Contains(link, "share") && !strings.Contains(link, "intent") {
				seen[link] = true
				links = append(links, link)
			}
		}
	}

	return links
}

// extractNumber extracts a number from text.
func extractNumber(text string) string {
	text = strings.TrimSpace(text)
	var numBuilder strings.Builder
	for _, ch := range text {
		if ch >= '0' && ch <= '9' {
			numBuilder.WriteRune(ch)
		} else if numBuilder.Len() > 0 {
			break
		}
	}
	return numBuilder.String()
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

func findElementWithClass(n *html.Node, className string) *html.Node {
	if n.Type == html.ElementNode && hasClass(n, className) {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if result := findElementWithClass(c, className); result != nil {
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
