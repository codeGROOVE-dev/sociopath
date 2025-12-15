// Package hackernews fetches Hacker News user profile data.
package hackernews

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "hackernews"

// platformInfo implements profile.Platform for Hacker News.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)news\.ycombinator\.com/user\?id=([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Hacker News user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "news.ycombinator.com/user?id=") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Hacker News profiles are public.
func AuthRequired() bool { return false }

// Client handles Hacker News requests.
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

// New creates a Hacker News client.
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

// apiUser represents the Hacker News API response.
type apiUser struct { //nolint:govet // field order matches API response
	Submitted []int  `json:"submitted"`
	ID        string `json:"id"`
	About     string `json:"about"`
	Created   int64  `json:"created"`
	Karma     int    `json:"karma"`
}

// apiItem represents a Hacker News item (story or comment).
type apiItem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	URL    string `json:"url"`
	Text   string `json:"text"`
	Time   int64  `json:"time"`
	ID     int    `json:"id"`
	Parent int    `json:"parent"`
}

// Fetch retrieves a Hacker News profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching hackernews profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://hacker-news.firebaseio.com/v0/user/%s.json", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	// HN API returns "null" for non-existent users
	if string(body) == "null" {
		return nil, profile.ErrProfileNotFound
	}

	var user apiUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse hackernews response: %w", err)
	}

	if user.ID == "" {
		return nil, profile.ErrProfileNotFound
	}

	p := parseProfile(&user, urlStr)

	// Fetch recent submissions (up to 15 items)
	if len(user.Submitted) > 0 {
		posts := c.fetchRecentItems(ctx, user.Submitted, 15)
		p.Posts = posts
	}

	return p, nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.ID,
		Name:     data.ID,
		Fields:   make(map[string]string),
	}

	// Parse creation date
	if data.Created > 0 {
		t := time.Unix(data.Created, 0)
		p.CreatedAt = t.Format("2006-01-02")
	}

	// Store karma
	if data.Karma > 0 {
		p.Fields["karma"] = strconv.Itoa(data.Karma)
	}

	// Parse about section (HTML encoded)
	if data.About != "" {
		// Decode HTML entities and strip tags for bio
		bio := html.UnescapeString(data.About)
		bio = stripHTMLTags(bio)
		bio = strings.TrimSpace(bio)
		if bio != "" {
			p.Bio = bio
		}

		// Extract links from about section
		p.SocialLinks = htmlutil.SocialLinks(data.About)

		// Extract email if present
		emails := htmlutil.EmailAddresses(data.About)
		if len(emails) > 0 {
			p.Fields["email"] = emails[0]
		}
	}

	return p
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// stripHTMLTags removes HTML tags from a string.
func stripHTMLTags(s string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	return re.ReplaceAllString(s, "")
}

// fetchRecentItems fetches up to maxItems recent submissions.
func (c *Client) fetchRecentItems(ctx context.Context, itemIDs []int, maxItems int) []profile.Post {
	if len(itemIDs) > maxItems {
		itemIDs = itemIDs[:maxItems]
	}

	var posts []profile.Post
	for _, id := range itemIDs {
		item, err := c.fetchItem(ctx, id)
		if err != nil {
			c.logger.DebugContext(ctx, "failed to fetch item", "id", id, "error", err)
			continue
		}
		if item == nil {
			continue
		}

		post := profile.Post{
			URL: fmt.Sprintf("https://news.ycombinator.com/item?id=%d", item.ID),
		}

		switch item.Type {
		case "story":
			post.Type = profile.PostTypePost
			post.Title = item.Title
			if item.URL != "" {
				post.Content = item.URL
			}
		case "comment":
			post.Type = profile.PostTypeComment
			text := html.UnescapeString(item.Text)
			text = stripHTMLTags(text)
			// Truncate long comments
			if len(text) > 200 {
				text = text[:200] + "..."
			}
			post.Content = text
		default:
			continue
		}

		posts = append(posts, post)
	}

	return posts
}

func (c *Client) fetchItem(ctx context.Context, id int) (*apiItem, error) {
	apiURL := fmt.Sprintf("https://hacker-news.firebaseio.com/v0/item/%d.json", id)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	if string(body) == "null" {
		return nil, nil //nolint:nilnil // intentional: nil item indicates "not found" without error
	}

	var item apiItem
	if err := json.Unmarshal(body, &item); err != nil {
		return nil, err
	}

	return &item, nil
}
