// Package intensedebate fetches IntenseDebate user profile data.
package intensedebate

import (
	"context"
	"encoding/xml"
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

const platform = "intensedebate"

var usernamePattern = regexp.MustCompile(`(?i)intensedebate\.com/people/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is an IntenseDebate profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "intensedebate.com/people/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because IntenseDebate profiles are public.
func AuthRequired() bool { return false }

// Client handles IntenseDebate requests.
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

// New creates an IntenseDebate client.
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

// rssFeed represents an IntenseDebate RSS feed.
type rssFeed struct {
	XMLName xml.Name   `xml:"rss"`
	Channel rssChannel `xml:"channel"`
}

type rssChannel struct {
	Title string    `xml:"title"`
	Items []rssItem `xml:"item"`
}

type rssItem struct {
	Title   string `xml:"title"`
	Link    string `xml:"link"`
	Content string `xml:"description"`
}

// Fetch retrieves an IntenseDebate profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	profileURL := fmt.Sprintf("https://www.intensedebate.com/people/%s", username)
	c.logger.InfoContext(ctx, "fetching intensedebate profile", "url", profileURL, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	content := string(body)

	// Check for invalid user
	if strings.Contains(content, "Invalid user name") {
		return nil, profile.ErrProfileNotFound
	}

	p := parseProfile(content, profileURL, username)

	// Fetch recent comments from RSS feed
	posts := c.fetchRecentComments(ctx, username, 15)
	p.Posts = posts

	return p, nil
}

func parseProfile(html, url, username string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Name:     username,
		Fields:   make(map[string]string),
	}

	// Try to extract better name from title
	title := htmlutil.Title(html)
	if name, found := strings.CutPrefix(title, "IntenseDebate - "); found && name != "" {
		p.Name = name
	}

	// Extract social links from profile
	p.SocialLinks = htmlutil.SocialLinks(html)

	return p
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// fetchRecentComments fetches recent comments from the IntenseDebate RSS feed.
func (c *Client) fetchRecentComments(ctx context.Context, username string, maxItems int) []profile.Post {
	feedURL := fmt.Sprintf("https://www.intensedebate.com/people/%s/comments.rss", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, http.NoBody)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to create RSS request", "error", err)
		return nil
	}
	req.Header.Set("User-Agent", "sociopath/1.0 (social profile aggregator)")
	req.Header.Set("Accept", "application/rss+xml, application/xml, text/xml")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to fetch RSS feed", "error", err)
		return nil
	}

	var feed rssFeed
	if err := xml.Unmarshal(body, &feed); err != nil {
		c.logger.DebugContext(ctx, "failed to parse RSS feed", "error", err)
		return nil
	}

	items := feed.Channel.Items
	if len(items) > maxItems {
		items = items[:maxItems]
	}

	var posts []profile.Post
	for _, item := range items {
		post := profile.Post{
			Type:  profile.PostTypeComment,
			Title: item.Title,
			URL:   item.Link,
		}
		// Strip HTML from content for preview
		content := stripHTML(item.Content)
		if len(content) > 200 {
			content = content[:200] + "..."
		}
		post.Content = content
		posts = append(posts, post)
	}

	return posts
}

// stripHTML removes HTML tags from a string.
func stripHTML(s string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	return strings.TrimSpace(re.ReplaceAllString(s, ""))
}
