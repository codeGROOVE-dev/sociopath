// Package virgool fetches Virgool profile data.
// Virgool is an Iranian blogging platform similar to Medium.
package virgool

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
)

const platform = "virgool"

// Pre-compiled patterns for URL matching and extraction.
var (
	usernamePattern = regexp.MustCompile(`virgool\.io/@([^/?#]+)`)
	followerPattern = regexp.MustCompile(`(\d+)\s*(?:دنبال‌کننده|Followers)`)
	followingPattern = regexp.MustCompile(`(\d+)\s*(?:دنبال شونده|Following)`)
)

// platformInfo implements profile.Platform for Virgool.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Virgool profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "virgool.io/@")
}

// AuthRequired returns false because Virgool profiles are public.
func AuthRequired() bool { return false }

// Client handles Virgool requests.
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

// New creates a Virgool client.
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

// Fetch retrieves a Virgool profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching virgool profile", "url", urlStr, "username", username)

	// Normalize URL
	profileURL := fmt.Sprintf("https://virgool.io/@%s", username)

	// Fetch HTML
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	p := &profile.Profile{
		Platform:   platform,
		URL:        profileURL,
		Username:   username,
		Confidence: 1.0,
	}

	// Extract data from HTML
	extractFromHTML(p, body)

	return p, nil
}

// extractUsername extracts the username from a Virgool URL.
func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractFromHTML extracts profile data from HTML content.
func extractFromHTML(p *profile.Profile, body []byte) {
	html := string(body)

	// Extract JSON-LD data if present
	if jsonData := htmlutil.ExtractJSONLD(html); jsonData != "" {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(jsonData), &data); err == nil {
			if name, ok := data["name"].(string); ok {
				p.DisplayName = strings.TrimSpace(name)
			}
			if desc, ok := data["description"].(string); ok {
				p.Bio = strings.TrimSpace(desc)
			}
			if img, ok := data["image"].(string); ok {
				p.AvatarURL = img
			}
		}
	}

	// Extract Open Graph data
	if name := htmlutil.ExtractMetaTag(html, "og:title"); name != "" {
		if p.DisplayName == "" {
			p.DisplayName = name
		}
	}
	if desc := htmlutil.ExtractMetaTag(html, "og:description"); desc != "" {
		if p.Bio == "" {
			p.Bio = desc
		}
	}
	if img := htmlutil.ExtractMetaTag(html, "og:image"); img != "" {
		if p.AvatarURL == "" {
			p.AvatarURL = img
		}
	}

	// Extract avatar from files.virgool.io pattern
	if avatarMatch := regexp.MustCompile(`https://files\.virgool\.io/upload/users/\d+/avatar/[^"'\s]+`).FindString(html); avatarMatch != "" {
		p.AvatarURL = avatarMatch
	}

	// Extract social links
	p.SocialLinks = extractSocialLinks(html)

	// Extract follower/following counts
	if matches := followerPattern.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["followers"] = matches[1]
	}
	if matches := followingPattern.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["following"] = matches[1]
	}

	// Extract posts/articles
	p.Posts = extractPosts(html)
}

// extractSocialLinks finds social media links in the profile.
func extractSocialLinks(html string) []string {
	var links []string
	seen := make(map[string]bool)

	// Twitter/X links
	if matches := regexp.MustCompile(`(?:twitter\.com|x\.com)/([a-zA-Z0-9_]+)`).FindAllStringSubmatch(html, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) > 1 && m[1] != "share" && m[1] != "intent" {
				link := "https://twitter.com/" + m[1]
				if !seen[link] {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	// Instagram links
	if matches := regexp.MustCompile(`instagram\.com/([a-zA-Z0-9_.]+)`).FindAllStringSubmatch(html, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) > 1 {
				link := "https://instagram.com/" + m[1]
				if !seen[link] {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	// Telegram links
	if matches := regexp.MustCompile(`t\.me/([a-zA-Z0-9_]+)`).FindAllStringSubmatch(html, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) > 1 {
				link := "https://t.me/" + m[1]
				if !seen[link] {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	// LinkedIn links
	if matches := regexp.MustCompile(`linkedin\.com/in/([a-zA-Z0-9_-]+)`).FindAllStringSubmatch(html, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) > 1 {
				link := "https://linkedin.com/in/" + m[1]
				if !seen[link] {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	// GitHub links
	if matches := regexp.MustCompile(`github\.com/([a-zA-Z0-9_-]+)`).FindAllStringSubmatch(html, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) > 1 && m[1] != "share" {
				link := "https://github.com/" + m[1]
				if !seen[link] {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	return links
}

// extractPosts extracts recent posts/articles from the profile.
func extractPosts(html string) []profile.Post {
	var posts []profile.Post

	// Extract article titles and links
	// Virgool uses patterns like /post-slug for articles
	articlePattern := regexp.MustCompile(`<a[^>]+href="/@[^/]+/([^"]+)"[^>]*>([^<]+)</a>`)
	matches := articlePattern.FindAllStringSubmatch(html, -1)

	for _, m := range matches {
		if len(m) > 2 {
			slug := m[1]
			title := htmlutil.DecodeHTMLEntities(strings.TrimSpace(m[2]))

			// Skip if title is too short or looks like UI text
			if len(title) < 3 || title == "" {
				continue
			}

			posts = append(posts, profile.Post{
				Title: title,
				URL:   fmt.Sprintf("https://virgool.io/@%s/%s", extractUsernameFromHTML(html), slug),
			})
		}
	}

	return posts
}

// extractUsernameFromHTML tries to extract the username from HTML content.
func extractUsernameFromHTML(html string) string {
	if matches := regexp.MustCompile(`virgool\.io/@([^/"']+)`).FindStringSubmatch(html); len(matches) > 1 {
		return matches[1]
	}
	return ""
}
