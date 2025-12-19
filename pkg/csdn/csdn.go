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

// platformInfo implements profile.Platform for CSDN.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

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
		Badges:   make(map[string]string),
	}

	var articles []profile.Post
	var columns []string
	var medals []string
	var activityYears []string

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Extract from title tag: "用户名-CSDN博客"
			if n.Data == "title" && n.FirstChild != nil {
				title := strings.TrimSpace(n.FirstChild.Data)
				if strings.Contains(title, "-CSDN") {
					parts := strings.Split(title, "-CSDN")
					if len(parts) > 0 && parts[0] != "" {
						p.DisplayName = strings.TrimSpace(parts[0])
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

			// Extract avatar URL
			if p.AvatarURL == "" {
				if hasClass(n, "user-profile-avatar") {
					if img := findElement(n, "img"); img != nil {
						if src := getAttribute(img, "src"); src != "" {
							p.AvatarURL = src
						}
					}
				}
			}

			// Extract location from IP attribution
			if hasClass(n, "address") {
				if text := getTextContent(n); text != "" {
					// Text is like "IP 属地：香港"
					if strings.Contains(text, "IP") && strings.Contains(text, "：") {
						parts := strings.Split(text, "：")
						if len(parts) > 1 {
							p.Fields["location"] = strings.TrimSpace(parts[1])
						}
					}
				}
			}

			// Extract join date
			if hasClass(n, "user-general-info-join-csdn-active") {
				if text := getTextContent(n); text != "" {
					// Text contains date like "加入CSDN时间：2019-09-29"
					if strings.Contains(text, "：") {
						parts := strings.Split(text, "：")
						if len(parts) > 1 {
							p.Fields["join_date"] = strings.TrimSpace(parts[1])
						}
					}
				}
			}

			// Extract code age (码龄)
			if hasClass(n, "person-code-age") {
				if span := findElement(n, "span"); span != nil {
					if text := getTextContent(span); text != "" {
						p.Fields["code_age"] = strings.TrimSpace(text)
					}
				}
			}

			// Extract statistics
			if hasClass(n, "user-profile-statistics-num") {
				numText := getTextContent(n)
				if parent := n.Parent; parent != nil {
					// Find the corresponding name
					if nameNode := findElementWithClass(parent, "user-profile-statistics-name"); nameNode != nil {
						nameText := getTextContent(nameNode)
						numText = strings.TrimSpace(numText)
						nameText = strings.TrimSpace(nameText)

						switch nameText {
						case "总访问量":
							p.Fields["total_views"] = numText
						case "原创":
							p.Fields["original_articles"] = numText
						case "排名":
							p.Fields["ranking"] = numText
						case "粉丝":
							p.Fields["followers"] = numText
						case "关注":
							p.Fields["following"] = numText
						default:
							// Unknown statistic type
						}
					}
				}
			}

			// Extract achievements (点赞, 收藏, 评论)
			if hasClass(n, "aside-common-box-content-text") {
				text := getTextContent(n)
				if span := findElement(n, "span"); span != nil {
					count := getTextContent(span)
					count = strings.TrimSpace(count)

					//nolint:gosmopolitan // Chinese text required for CSDN content
					switch {
					case strings.Contains(text, "点赞"):
						p.Fields["likes_received"] = count
					case strings.Contains(text, "收藏"):
						p.Fields["collections"] = count
					case strings.Contains(text, "评论"):
						p.Fields["comments_received"] = count
					default:
						// Unknown achievement type
					}
				}
			}

			// Extract articles from blog-list-box
			if hasClass(n, "blog-list-box") {
				article := extractArticle(n)
				if article.Title != "" {
					articles = append(articles, article)
				}
			}

			// Extract columns from special-column section
			if hasClass(n, "special-column-name") {
				extractColumns(n, &columns)
			}

			// Extract medals from medal images
			if hasClass(n, "aside-common-box-medal") {
				extractMedals(n, &medals)
			}

			// Extract activity by year
			if hasClass(n, "aside-common-box-create") {
				extractActivity(n, &activityYears)
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(doc)

	// Add collected data to profile
	if len(articles) > 0 {
		p.Posts = articles
	}
	if len(columns) > 0 {
		p.Groups = columns
	}
	if len(medals) > 0 {
		for i, medal := range medals {
			p.Badges[fmt.Sprintf("medal_%d", i+1)] = medal
		}
	}
	if len(activityYears) > 0 {
		for i, activity := range activityYears {
			p.Fields[fmt.Sprintf("activity_year_%d", i+1)] = activity
		}
	}

	// Default name if not found
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	// Check for not found
	if strings.Contains(string(body), "404") || strings.Contains(string(body), "用户不存在") {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

// extractArticle extracts article data from a blog-list-box node.
func extractArticle(n *html.Node) profile.Post {
	article := profile.Post{Type: profile.PostTypeArticle}

	// Find the link element
	var link *html.Node
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "a" {
			link = c
			break
		}
	}

	if link == nil {
		return article
	}

	// Extract URL
	article.URL = getAttribute(link, "href")
	if !strings.HasPrefix(article.URL, "http") {
		article.URL = "https://blog.csdn.net" + article.URL
	}

	// Extract title
	if titleNode := findElementWithClass(link, "blog-list-box-top"); titleNode != nil {
		if h4 := findElement(titleNode, "h4"); h4 != nil {
			article.Title = strings.TrimSpace(getTextContent(h4))
		}
	}

	// Extract content preview
	if contentNode := findElementWithClass(link, "blog-list-content"); contentNode != nil {
		article.Content = strings.TrimSpace(getTextContent(contentNode))
	}

	// Extract date
	if footer := findElementWithClass(link, "blog-list-footer"); footer != nil {
		if timeBox := findElementWithClass(footer, "view-time-box"); timeBox != nil {
			dateText := getTextContent(timeBox)
			// Text like "博文更新于 2025.12.16 ·"
			dateText = strings.TrimSpace(dateText)
			dateText = strings.TrimSuffix(dateText, "·")
			dateText = strings.TrimSpace(dateText)
			if strings.Contains(dateText, "：") {
				parts := strings.Split(dateText, "：")
				if len(parts) > 1 {
					article.Date = strings.TrimSpace(parts[1])
				}
				//nolint:gosmopolitan // Chinese text required for CSDN content
			} else if strings.Contains(dateText, "于 ") {
				//nolint:gosmopolitan // Chinese text required for CSDN content
				parts := strings.Split(dateText, "于 ")
				if len(parts) > 1 {
					article.Date = strings.TrimSpace(parts[1])
				}
			}
		}

		// Extract article type (原创, 转载, 翻译)
		if typeNode := findElementWithClass(footer, "article-type"); typeNode != nil {
			articleType := strings.TrimSpace(getTextContent(typeNode))
			if articleType != "" {
				article.Category = articleType
			}
		}

		// Extract view count, likes, comments as additional metadata
		//nolint:gosmopolitan // Chinese text required for CSDN content
		var metadata []string
		if viewNum := findElementWithClass(footer, "view-num"); viewNum != nil {
			//nolint:gosmopolitan // Chinese text required for CSDN content
			if text := getTextContent(viewNum); text != "" {
				metadata = append(metadata, strings.TrimSpace(text)+" 阅读")
			}
		}
		if likes := findElementWithClass(footer, "give-like-num"); likes != nil {
			//nolint:gosmopolitan // Chinese text required for CSDN content
			if text := getTextContent(likes); text != "" {
				metadata = append(metadata, strings.TrimSpace(text)+" 点赞")
			}
		}
		if comments := findElementWithClass(footer, "comment-num"); comments != nil {
			//nolint:gosmopolitan // Chinese text required for CSDN content
			if text := getTextContent(comments); text != "" {
				text = strings.TrimSpace(text)
				// Avoid duplication - comment-box can appear multiple times
				if !sliceContains(metadata, text+" 评论") && !strings.Contains(text, "收藏") {
					metadata = append(metadata, text+" 评论")
				}
			}
		}

		if len(metadata) > 0 {
			if article.Content != "" {
				article.Content += "\n\n"
			}
			article.Content += "[" + strings.Join(metadata, ", ") + "]"
		}
	}

	return article
}

// extractColumns extracts column names from a special-column-name node.
func extractColumns(n *html.Node, columns *[]string) {
	if link := findElement(n, "span"); link != nil {
		columnName := getTextContent(link)
		columnName = strings.TrimSpace(columnName)
		if columnName != "" && !sliceContains(*columns, columnName) {
			*columns = append(*columns, columnName)
		}
	}
}

// extractMedals extracts medal URLs from a medal box node.
func extractMedals(n *html.Node, medals *[]string) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "li" {
			if img := findElement(c, "img"); img != nil {
				medalURL := getAttribute(img, "src")
				if medalURL != "" && !sliceContains(*medals, medalURL) {
					*medals = append(*medals, medalURL)
				}
			}
		}
	}
}

// extractActivity extracts activity year entries from an activity box node.
func extractActivity(n *html.Node, activityYears *[]string) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "li" {
			if a := findElement(c, "a"); a != nil {
				countDiv := findElementWithClass(a, "count")
				timeDiv := findElementWithClass(a, "time")
				if countDiv != nil && timeDiv != nil {
					count := strings.TrimSpace(getTextContent(countDiv))
					year := strings.TrimSpace(getTextContent(timeDiv))
					if count != "" && year != "" {
						entry := year + ": " + count
						if !sliceContains(*activityYears, entry) {
							*activityYears = append(*activityYears, entry)
						}
					}
				}
			}
		}
	}
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

func sliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
