// Package arstechnica fetches Ars Technica forum profile data.
package arstechnica

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/profile"

	"golang.org/x/net/html"
)

const platform = "arstechnica"

// platformInfo implements profile.Platform for Ars Technica.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// URL patterns:
// Search URL with ID: arstechnica.com/civis/search/{search_id}/?c[users]={username}&o=date.
// Search URL without ID: arstechnica.com/civis/search/?c[users]={username}&o=date.
// Member URL: arstechnica.com/civis/members/{username}.{user_id}/.
var (
	// Match both URL-encoded (%5B/%5D) and literal brackets.
	searchPatternWithID = regexp.MustCompile(`(?i)arstechnica\.com/civis/search/(\d+)/?\?.*c(?:\[|%5[Bb])users(?:\]|%5[Dd])=([a-zA-Z0-9_-]+)`)
	searchPatternNoID   = regexp.MustCompile(`(?i)arstechnica\.com/civis/search/\?.*c(?:\[|%5[Bb])users(?:\]|%5[Dd])=([a-zA-Z0-9_-]+)`)
	memberPattern       = regexp.MustCompile(`(?i)arstechnica\.com/civis/members/([a-zA-Z0-9_-]+)\.(\d+)`)
)

// Match returns true if the URL is an Ars Technica forum profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "arstechnica.com/civis/") {
		return false
	}
	return searchPatternWithID.MatchString(urlStr) || searchPatternNoID.MatchString(urlStr) || memberPattern.MatchString(urlStr)
}

// AuthRequired returns false because Ars Technica forum profiles are publicly viewable.
func AuthRequired() bool { return false }

// Client handles Ars Technica requests.
type Client struct {
	httpClient *http.Client
	logger     *slog.Logger
}

// Option configures a Client.
type Option func(*config)

type config struct {
	logger *slog.Logger
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates an Ars Technica client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Jar:     jar,
		},
		logger: cfg.logger,
	}, nil
}

// tooltipResponse represents the JSON response from the XenForo tooltip API.
type tooltipResponse struct {
	Status string `json:"status"`
	HTML   struct {
		Content string `json:"content"`
	} `json:"html"`
}

// Fetch retrieves an Ars Technica forum member profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	var username, userID string
	var posts []profile.Post

	// Check if it's a search URL with ID - need to fetch page to get real user ID
	if matches := searchPatternWithID.FindStringSubmatch(urlStr); len(matches) > 2 {
		username = matches[2]
		c.logger.InfoContext(ctx, "fetching arstechnica search page", "url", urlStr, "username", username)

		// Fetch search page to extract actual user ID and posts
		var err error
		userID, posts, err = c.extractFromSearch(ctx, urlStr)
		if err != nil {
			return nil, fmt.Errorf("failed to extract user ID from search: %w", err)
		}
	} else if matches := searchPatternNoID.FindStringSubmatch(urlStr); len(matches) > 1 {
		// Search URL without ID (e.g., from guess)
		username = matches[1]
		c.logger.InfoContext(ctx, "fetching arstechnica search page (no id)", "url", urlStr, "username", username)

		// Fetch search page to extract actual user ID and posts
		var err error
		userID, posts, err = c.extractFromSearch(ctx, urlStr)
		if err != nil {
			return nil, fmt.Errorf("failed to extract user ID from search: %w", err)
		}
	} else if matches := memberPattern.FindStringSubmatch(urlStr); len(matches) > 2 {
		username = matches[1]
		userID = matches[2]
		// For direct member URLs, construct and fetch search URL to get posts.
		// Ignore errors here since posts are optional (profile info comes from tooltip).
		searchURL := fmt.Sprintf("https://arstechnica.com/civis/search/?c[users]=%s&o=date", username)
		_, posts, _ = c.extractFromSearch(ctx, searchURL) //nolint:errcheck // posts are optional
	} else {
		return nil, fmt.Errorf("could not extract member info from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching arstechnica profile", "username", username, "user_id", userID)

	// Get CSRF token (this also sets session cookies)
	csrfToken, err := c.fetchCSRFToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get CSRF token: %w", err)
	}
	c.logger.DebugContext(ctx, "got csrf token", "token", csrfToken)

	// Fetch tooltip with user data
	p, err := c.fetchTooltip(ctx, username, userID, csrfToken)
	if err != nil {
		return nil, err
	}

	p.Posts = posts
	return p, nil
}

func (c *Client) extractFromSearch(ctx context.Context, searchURL string) (string, []profile.Post, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, http.NoBody)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // defer closes body

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("unexpected status %d fetching search page", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read search page: %w", err)
	}

	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse search HTML: %w", err)
	}

	// Look for data-user-id attribute in member links
	var userID string
	var findUserID func(*html.Node)
	findUserID = func(n *html.Node) {
		if userID != "" {
			return
		}
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "data-user-id" && attr.Val != "" {
					userID = attr.Val
					return
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			findUserID(child)
		}
	}
	findUserID(doc)

	if userID == "" {
		return "", nil, errors.New("could not find user ID in search results")
	}

	// Extract posts from search results
	posts := extractPostsFromSearch(string(body))

	return userID, posts, nil
}

func extractPostsFromSearch(htmlContent string) []profile.Post {
	// Pattern to match contentRow-title links
	titlePattern := regexp.MustCompile(`<h3 class="contentRow-title">\s*<a href="(/civis/threads/[^"]+)">([^<]+)</a>`)
	matches := titlePattern.FindAllStringSubmatch(htmlContent, 15)

	var posts []profile.Post
	for _, m := range matches {
		if len(m) > 2 {
			posts = append(posts, profile.Post{
				Type:  profile.PostTypeComment,
				Title: strings.TrimSpace(m[2]),
				URL:   "https://arstechnica.com" + m[1],
			})
		}
	}

	return posts
}

func (c *Client) fetchCSRFToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://arstechnica.com/civis/", http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck // defer closes body

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d fetching civis page", resp.StatusCode)
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to parse HTML: %w", err)
	}

	var csrfToken string
	var findCSRF func(*html.Node)
	findCSRF = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "html" {
			for _, attr := range n.Attr {
				if attr.Key == "data-csrf" {
					csrfToken = attr.Val
					return
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			if csrfToken != "" {
				return
			}
			findCSRF(child)
		}
	}
	findCSRF(doc)

	if csrfToken == "" {
		return "", errors.New("could not find data-csrf token")
	}

	return csrfToken, nil
}

func (c *Client) fetchTooltip(ctx context.Context, username, userID, csrfToken string) (*profile.Profile, error) {
	tooltipURL := fmt.Sprintf(
		"https://arstechnica.com/civis/members/%s.%s/?tooltip=true&_xfRequestUri=%s&_xfWithData=1&_xfToken=%s&_xfResponseType=json",
		username, userID, url.QueryEscape("/civis/"), csrfToken,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tooltipURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // defer closes body

	if resp.StatusCode == http.StatusNotFound {
		return nil, profile.ErrProfileNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching tooltip", resp.StatusCode)
	}

	var tooltipResp tooltipResponse
	if err := json.NewDecoder(resp.Body).Decode(&tooltipResp); err != nil {
		return nil, fmt.Errorf("failed to decode tooltip JSON: %w", err)
	}

	if tooltipResp.Status != "ok" {
		return nil, fmt.Errorf("tooltip API returned status: %s", tooltipResp.Status)
	}

	return parseTooltipHTML(tooltipResp.HTML.Content, username, userID)
}

func parseTooltipHTML(htmlContent, username, userID string) (*profile.Profile, error) {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse tooltip HTML: %w", err)
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      fmt.Sprintf("https://arstechnica.com/civis/members/%s.%s/", username, userID),
		Username: username,
		Fields:   make(map[string]string),
	}
	p.Fields["user_id"] = userID

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			classes := getAttr(n, "class")

			// Extract username from memberTooltip-name
			if n.Data == "h4" && strings.Contains(classes, "memberTooltip-name") {
				if name := extractText(n); name != "" {
					p.Name = strings.TrimSpace(name)
				}
			}

			// Extract title from userTitle span
			if n.Data == "span" && strings.Contains(classes, "userTitle") {
				if title := extractText(n); title != "" {
					p.Fields["title"] = strings.TrimSpace(title)
				}
			}

			// Extract stats from dl.pairs elements
			if n.Data == "dt" {
				label := strings.ToLower(strings.TrimSpace(extractText(n)))
				if dd := findNextSibling(n, "dd"); dd != nil {
					value := strings.TrimSpace(extractText(dd))
					switch label {
					case "joined":
						p.Fields["joined"] = value
					case "last seen":
						p.Fields["last_seen"] = value
					case "messages":
						p.Fields["messages"] = value
					case "reaction score":
						p.Fields["reaction_score"] = value
					default:
						// Ignore other labels
					}
				}
			}
		}

		for child := n.FirstChild; child != nil; child = child.NextSibling {
			extract(child)
		}
	}

	extract(doc)

	if p.Name == "" {
		p.Name = username
	}

	return p, nil
}

func getAttr(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

func extractText(n *html.Node) string {
	var text strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			text.WriteString(node.Data)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
	return text.String()
}

func findNextSibling(n *html.Node, tag string) *html.Node {
	for sibling := n.NextSibling; sibling != nil; sibling = sibling.NextSibling {
		if sibling.Type == html.ElementNode && sibling.Data == tag {
			return sibling
		}
	}
	return nil
}
