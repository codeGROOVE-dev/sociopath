// Package dou fetches DOU.ua (developers.org.ua) profile data.
package dou

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

const platform = "dou"

// platformInfo implements profile.Platform for DOU.ua.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)dou\.ua/users/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a DOU.ua profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "dou.ua/users/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because DOU.ua profiles are public.
func AuthRequired() bool { return false }

// Client handles DOU.ua requests.
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

// New creates a DOU.ua client.
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

// Fetch retrieves a DOU.ua profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	profileURL := fmt.Sprintf("https://dou.ua/users/%s", username)
	c.logger.InfoContext(ctx, "fetching dou profile", "url", profileURL, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "uk,en;q=0.9")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	prof, err := parseProfile(string(body), username, profileURL)
	if err != nil {
		return nil, err
	}

	// Fetch articles page to get posts
	articlesURL := fmt.Sprintf("https://dou.ua/users/%s/articles/", username)
	c.logger.InfoContext(ctx, "fetching dou articles", "url", articlesURL)

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, articlesURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "uk,en;q=0.9")

	articlesBody, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		c.logger.WarnContext(ctx, "failed to fetch articles page", "error", err)
	} else {
		posts := parseArticles(string(articlesBody))
		prof.Posts = posts
	}

	return prof, nil
}

func parseProfile(htmlContent, username, url string) (*profile.Profile, error) {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse dou HTML: %w", err)
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract from meta tags
	p.PageTitle = htmlutil.Title(htmlContent)
	if p.PageTitle != "" {
		// Title format: "Name | DOU"
		if idx := strings.Index(p.PageTitle, " | DOU"); idx != -1 {
			p.DisplayName = strings.TrimSpace(p.PageTitle[:idx])
		} else {
			p.DisplayName = p.PageTitle
		}
	}

	// Extract bio from meta description
	p.Bio = htmlutil.Description(htmlContent)

	// Extract avatar URL from og:image meta tag
	ogImagePattern := regexp.MustCompile(`<meta property="og:image" content="([^"]+)"`)
	if matches := ogImagePattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		p.AvatarURL = matches[1]
	}

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Extract job title and company from "descr" div
			if n.Data == "div" && hasClass(n, "descr") {
				jobText := getTextContent(n)
				jobText = strings.TrimSpace(jobText)
				if jobText != "" {
					// Format: "Position в Company"
					parts := strings.Split(jobText, " в ")
					if len(parts) == 2 {
						p.Fields["job_title"] = strings.TrimSpace(parts[0])
						p.Fields["company"] = strings.TrimSpace(parts[1])
					} else {
						p.Fields["job_title"] = jobText
					}
				}

				// Extract company URL
				if companyLink := findElementWithClass(n, "company"); companyLink != nil {
					if href := getAttribute(companyLink, "href"); href != "" {
						p.Fields["company_url"] = href
					}
				}
			}

			// Extract subscriber count
			if hasClass(n, "mf_subscribers") {
				if text := getTextContent(n); text != "" {
					// Extract just the number
					numPattern := regexp.MustCompile(`\d+`)
					if match := numPattern.FindString(text); match != "" {
						p.Fields["subscribers"] = match
					}
				}
			}

			// Extract article, comment, and topic counts from content menu
			if n.Data == "li" && n.Parent != nil && hasClass(n.Parent, "b-content-menu") {
				linkText := getTextContent(n)

				// Extract count from <sub> tag
				var count string
				if sub := findElement(n, "sub"); sub != nil {
					count = strings.TrimSpace(getTextContent(sub))
				}

				if count != "" {
					if strings.Contains(linkText, "Коментарі") || strings.Contains(linkText, "Comments") {
						p.Fields["comments"] = count
					} else if strings.Contains(linkText, "Статті") || strings.Contains(linkText, "Articles") {
						p.Fields["articles"] = count
					} else if strings.Contains(linkText, "Топіки") || strings.Contains(linkText, "Topics") {
						p.Fields["topics"] = count
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
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	// Check for not found
	if strings.Contains(htmlContent, "404") || strings.Contains(htmlContent, "не знайдено") {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func parseArticles(htmlContent string) []profile.Post {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil
	}

	var posts []profile.Post

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "article" && hasClass(n, "b-postcard") {
			post := extractArticle(n)
			if post.Title != "" {
				posts = append(posts, post)
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(doc)
	return posts
}

func extractArticle(n *html.Node) profile.Post {
	post := profile.Post{Type: profile.PostTypeArticle}

	// Extract title and URL
	if titleH2 := findElementWithClass(n, "title"); titleH2 != nil {
		if link := findElement(titleH2, "a"); link != nil {
			post.Title = strings.TrimSpace(getTextContent(link))
			post.URL = getAttribute(link, "href")
			// Ensure absolute URL
			if post.URL != "" && !strings.HasPrefix(post.URL, "http") {
				post.URL = "https://dou.ua" + post.URL
			}
		}
	}

	// Extract date, author, and view count from b-info
	if infoDiv := findElementWithClass(n, "b-info"); infoDiv != nil {
		// Extract date
		if timeEl := findElement(infoDiv, "time"); timeEl != nil {
			dateText := getTextContent(timeEl)
			post.Date = strings.TrimSpace(dateText)
		}

		// Extract view count
		if viewSpan := findElementWithClass(infoDiv, "pageviews"); viewSpan != nil {
			viewCount := strings.TrimSpace(getTextContent(viewSpan))
			if viewCount != "" {
				post.Content += "[" + viewCount + " views"
			}
		}
	}

	// Extract description from b-typo
	if descP := findElementWithClass(n, "b-typo"); descP != nil {
		desc := getTextContent(descP)
		desc = strings.TrimSpace(desc)

		// Extract comment count from the description if present
		commentPattern := regexp.MustCompile(`(\d+)\s*$`)
		if matches := commentPattern.FindStringSubmatch(desc); len(matches) > 1 {
			commentCount := matches[1]
			// Remove comment indicator from description
			desc = strings.TrimSpace(strings.TrimSuffix(desc, matches[0]))
			if post.Content != "" {
				post.Content += ", " + commentCount + " comments]"
			} else {
				post.Content = "[" + commentCount + " comments]"
			}
		} else if post.Content != "" {
			post.Content += "]"
		}

		// Add description
		if desc != "" {
			if post.Content != "" {
				post.Content = desc + "\n\n" + post.Content
			} else {
				post.Content = desc
			}
		}
	}

	// Extract category and tags from "more" div
	if moreDiv := findElementWithClass(n, "more"); moreDiv != nil {
		// Extract category (topic)
		if topicLink := findElementWithClass(moreDiv, "topic"); topicLink != nil {
			post.Category = strings.TrimSpace(getTextContent(topicLink))
		}

		// Extract all links as tags (after the category)
		var tags []string
		var extractTags func(*html.Node)
		extractTags = func(node *html.Node) {
			if node.Type == html.ElementNode && node.Data == "a" {
				// Skip the topic link (category)
				if !hasClass(node, "topic") {
					tag := strings.TrimSpace(getTextContent(node))
					if tag != "" {
						tags = append(tags, tag)
					}
				}
			}
			for c := node.FirstChild; c != nil; c = c.NextSibling {
				extractTags(c)
			}
		}
		extractTags(moreDiv)

		// Add tags to content as metadata
		if len(tags) > 0 {
			tagStr := "Tags: " + strings.Join(tags, ", ")
			if post.Content != "" {
				post.Content += "\n" + tagStr
			} else {
				post.Content = tagStr
			}
		}
	}

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
