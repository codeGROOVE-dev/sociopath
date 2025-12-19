// Package kaskus fetches Kaskus forum profile data.
// Kaskus is Indonesia's largest online community and forum.
package kaskus

import (
	"context"
	"encoding/json"
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

const platform = "kaskus"

// platformInfo implements profile.Platform for Kaskus.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Pre-compiled patterns for URL matching.
var (
	newUsernamePattern = regexp.MustCompile(`(?i)kaskus\.co\.id/@([a-zA-Z0-9_-]+)`)
	oldUserIDPattern   = regexp.MustCompile(`(?i)kaskus\.co\.id/profile/(\d+)`)
)

// Match returns true if the URL is a Kaskus profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "kaskus.co.id/") {
		return false
	}
	// Exclude non-profile URLs
	excludePatterns := []string{
		"/thread/", "/forum/", "/post/", "/search/",
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(lower, pattern) {
			return false
		}
	}
	return newUsernamePattern.MatchString(urlStr) || oldUserIDPattern.MatchString(urlStr)
}

// AuthRequired returns false because Kaskus profiles are public.
func AuthRequired() bool { return false }

// Client handles Kaskus requests.
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

// New creates a Kaskus client.
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

// Fetch retrieves a Kaskus profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching kaskus profile", "url", urlStr, "username", username)

	// Normalize to new format
	profileURL := fmt.Sprintf("https://www.kaskus.co.id/@%s", username)

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

	c.logger.InfoContext(ctx, "parsed kaskus profile",
		"display_name", p.DisplayName,
		"avatar_url", p.AvatarURL,
		"bio", p.Bio,
		"fields_count", len(p.Fields),
		"posts_count", len(p.Posts),
		"badges_count", len(p.Badges))

	return p, nil
}

//nolint:gosmopolitan // Indonesian text for error detection
func parseHTML(body []byte, username, url string) (*profile.Profile, error) {
	bodyStr := string(body)

	// Check for not found
	//nolint:gosmopolitan // Indonesian text for error detection
	if strings.Contains(bodyStr, "User not found") ||
		strings.Contains(bodyStr, "Pengguna tidak ditemukan") ||
		strings.Contains(bodyStr, "Halaman tidak ditemukan") ||
		strings.Contains(bodyStr, "404") {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
		Badges:   make(map[string]string),
	}

	// Try to extract from Next.js JSON data in <script> tags
	if extractedFromJSON(bodyStr, p) {
		return p, nil
	}

	// Fall back to HTML parsing
	doc, err := html.Parse(strings.NewReader(bodyStr))
	if err != nil {
		return nil, fmt.Errorf("failed to parse kaskus HTML: %w", err)
	}

	extractFromHTML(doc, p, bodyStr)

	// Default name if not found
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	return p, nil
}

// extractedFromJSON tries to extract profile data from Next.js JSON in <script> tags.
func extractedFromJSON(bodyStr string, p *profile.Profile) bool {
	// Look for Next.js __NEXT_DATA__ script tag
	pattern := regexp.MustCompile(`(?s)<script[^>]+id="__NEXT_DATA__"[^>]*>(.*?)</script>`)
	matches := pattern.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return false
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(matches[1]), &data); err != nil {
		return false
	}

	// Extract profile data from Next.js data structure
	// This is a best-effort extraction based on common Next.js patterns
	if props, ok := data["props"].(map[string]interface{}); ok {
		if pageProps, ok := props["pageProps"].(map[string]interface{}); ok {
			if user, ok := pageProps["user"].(map[string]interface{}); ok {
				if name, ok := user["displayName"].(string); ok {
					p.DisplayName = name
				}
				if username, ok := user["username"].(string); ok && p.Username == "" {
					p.Username = username
				}
				if avatar, ok := user["avatar"].(string); ok {
					p.AvatarURL = avatar
				}
				if bio, ok := user["bio"].(string); ok {
					p.Bio = bio
				}
				if posts, ok := user["postCount"].(float64); ok {
					p.Fields["posts"] = fmt.Sprintf("%.0f", posts)
				}
				if threads, ok := user["threadCount"].(float64); ok {
					p.Fields["threads"] = fmt.Sprintf("%.0f", threads)
				}
				if rep, ok := user["reputation"].(float64); ok {
					p.Fields["reputation"] = fmt.Sprintf("%.0f", rep)
				}
				if joinDate, ok := user["joinDate"].(string); ok {
					p.CreatedAt = joinDate
				}
				return true
			}
		}
	}

	return false
}

// extractFromHTML extracts profile data from HTML when JSON is not available.
func extractFromHTML(doc *html.Node, p *profile.Profile, bodyStr string) {
	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Extract from title tag
			if n.Data == "title" && n.FirstChild != nil {
				title := strings.TrimSpace(n.FirstChild.Data)
				// Format: "Username - Kaskus" or "Username"
				if strings.Contains(title, " - Kaskus") {
					parts := strings.Split(title, " - Kaskus")
					if len(parts) > 0 && parts[0] != "" {
						p.DisplayName = strings.TrimSpace(parts[0])
					}
				} else if title != "" && title != "Kaskus" {
					p.DisplayName = title
				}
			}

			// Extract meta tags
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
				if (property == "og:image" || name == "twitter:image") && content != "" && p.AvatarURL == "" {
					p.AvatarURL = content
				}
			}

			// Extract avatar from img tags
			if p.AvatarURL == "" {
				if hasClass(n, "avatar") || hasClass(n, "profile-image") || hasClass(n, "user-avatar") {
					if n.Data == "img" {
						if src := getAttribute(n, "src"); src != "" {
							p.AvatarURL = src
						}
					}
				}
			}

			// Extract bio from bio/about section
			if hasClass(n, "bio") || hasClass(n, "about") || hasClass(n, "signature") {
				if text := getTextContent(n); text != "" && len(text) > 10 {
					text = strings.TrimSpace(text)
					if p.Bio == "" || text != "masih malu-malu" {
						p.Bio = text
					}
				}
			}

			// Extract stats
			if hasClass(n, "post-count") || hasClass(n, "posts") {
				if text := extractNumber(getTextContent(n)); text != "" {
					p.Fields["posts"] = text
				}
			}
			if hasClass(n, "thread-count") || hasClass(n, "threads") {
				if text := extractNumber(getTextContent(n)); text != "" {
					p.Fields["threads"] = text
				}
			}
			if hasClass(n, "reputation") || hasClass(n, "karma") {
				if text := extractNumber(getTextContent(n)); text != "" {
					p.Fields["reputation"] = text
				}
			}

			// Extract badges
			if hasClass(n, "badge") || hasClass(n, "rank") {
				badgeText := strings.TrimSpace(getTextContent(n))
				if badgeText != "" && len(badgeText) < 100 {
					badgeKey := fmt.Sprintf("badge_%d", len(p.Badges)+1)
					p.Badges[badgeKey] = badgeText
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(doc)

	// Extract Open Graph data
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
}

// extractNumber extracts a number from text.
func extractNumber(text string) string {
	text = strings.TrimSpace(text)
	var numBuilder strings.Builder
	for _, ch := range text {
		if ch >= '0' && ch <= '9' {
			numBuilder.WriteRune(ch)
		} else if ch == ',' || ch == '.' {
			// Skip separators
			continue
		} else if numBuilder.Len() > 0 {
			// Stop at first non-digit after starting
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
	// Try new format first
	matches := newUsernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	// Try old format
	matches = oldUserIDPattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
