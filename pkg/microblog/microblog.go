// Package microblog fetches Micro.blog profile data.
package microblog

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "microblog"

var usernamePattern = regexp.MustCompile(`(?i)micro\.blog/([a-zA-Z0-9_]+)`)

// Match returns true if the URL is a Micro.blog profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "micro.blog/") {
		return false
	}
	// Exclude common non-profile paths
	if strings.Contains(lower, "/about") || strings.Contains(lower, "/signin") ||
		strings.Contains(lower, "/register") || strings.Contains(lower, "/posts/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Micro.blog profiles are public.
func AuthRequired() bool { return false }

// Client handles Micro.blog requests.
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

// New creates a Micro.blog client.
func New(_ context.Context, opts ...Option) (*Client, error) {
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

// jsonFeed represents the Micro.blog JSON feed response.
type jsonFeed struct {
	Title     string `json:"title"`
	Microblog *struct {
		ID             string `json:"id"`
		Username       string `json:"username"`
		Bio            string `json:"bio"`
		Pronouns       string `json:"pronouns"`
		FollowingCount int    `json:"following_count"`
	} `json:"_microblog"`
	Author *struct {
		Name   string `json:"name"`
		URL    string `json:"url"`
		Avatar string `json:"avatar"`
	} `json:"author"`
	Items []feedItem `json:"items"`
}

//nolint:govet // fieldalignment not critical for JSON parsing
type feedItem struct {
	ID          string    `json:"id"`
	ContentHTML string    `json:"content_html"`
	Summary     string    `json:"summary"`
	URL         string    `json:"url"`
	Published   string    `json:"date_published"`
	Microblog   *struct { //nolint:govet // fieldalignment not critical
		IsLinkpost  bool     `json:"is_linkpost"`
		Syndication []string `json:"syndication"`
	} `json:"_microblog"`
}

// Fetch retrieves a Micro.blog profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching microblog profile", "url", urlStr, "username", username)

	// Fetch JSON feed
	feedURL := fmt.Sprintf("https://micro.blog/posts/%s", username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var feed jsonFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("failed to parse microblog feed: %w", err)
	}

	if feed.Microblog == nil || feed.Microblog.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(ctx, &feed, urlStr, c.logger), nil
}

func parseProfile(ctx context.Context, feed *jsonFeed, profileURL string, logger *slog.Logger) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: feed.Microblog.Username,
		Fields:   make(map[string]string),
	}

	if feed.Author != nil {
		p.Name = feed.Author.Name
		p.AvatarURL = feed.Author.Avatar
		if feed.Author.URL != "" {
			p.Website = feed.Author.URL
			p.Fields["blog"] = feed.Author.URL
		}
	}

	if feed.Microblog.Bio != "" {
		p.Bio = feed.Microblog.Bio
	}

	if feed.Microblog.Pronouns != "" {
		p.Fields["pronouns"] = feed.Microblog.Pronouns
	}

	if feed.Microblog.ID != "" {
		p.Fields["id"] = feed.Microblog.ID
	}

	// Add Fediverse handle as social link
	fediverseHandle := fmt.Sprintf("@%s@micro.blog", feed.Microblog.Username)
	p.Fields["fediverse"] = fediverseHandle

	// Extract social links from syndication in posts
	seenLinks := make(map[string]bool)
	for _, item := range feed.Items {
		if item.Microblog != nil {
			for _, link := range item.Microblog.Syndication {
				if !seenLinks[link] {
					seenLinks[link] = true
					// Extract platform-specific links
					if strings.Contains(link, "bsky.app") {
						p.SocialLinks = append(p.SocialLinks, link)
						logger.InfoContext(ctx, "discovered social link from microblog",
							"platform", "bluesky", "link", link, "source", "microblog")
					} else if strings.Contains(link, "mastodon") || strings.Contains(link, "treehouse.systems") {
						p.SocialLinks = append(p.SocialLinks, link)
						logger.InfoContext(ctx, "discovered social link from microblog",
							"platform", "mastodon", "link", link, "source", "microblog")
					}
				}
			}
		}
	}

	// Add blog posts (linkposts only - these are actual blog entries)
	for _, item := range feed.Items {
		if item.Microblog != nil && item.Microblog.IsLinkpost && item.URL != "" {
			title := extractTitleFromHTML(item.ContentHTML)
			if title == "" {
				title = item.Summary
			}
			if title != "" {
				p.Posts = append(p.Posts, profile.Post{
					Type:  profile.PostTypeArticle,
					Title: title,
					URL:   item.URL,
				})
			}
			// Limit posts
			if len(p.Posts) >= 10 {
				break
			}
		}
	}

	return p
}

func extractTitleFromHTML(html string) string {
	// Extract text from simple HTML like "<p>Title: <a href="...">domain</a></p>"
	// Look for link text
	linkStart := strings.Index(html, `<a href="`)
	if linkStart == -1 {
		return ""
	}
	// Find the text before the link
	prefix := html[:linkStart]
	prefix = strings.TrimPrefix(prefix, "<p>")
	prefix = strings.TrimSpace(prefix)
	if prefix != "" && !strings.HasSuffix(prefix, ":") {
		return prefix
	}
	return ""
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		username := matches[1]
		// Remove query parameters
		if idx := strings.Index(username, "?"); idx > 0 {
			username = username[:idx]
		}
		return username
	}
	return ""
}
