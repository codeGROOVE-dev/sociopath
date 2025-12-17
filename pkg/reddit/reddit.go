// Package reddit fetches Reddit user profile data.
package reddit

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
)

const platform = "reddit"

// Pre-compiled patterns for parsing Reddit HTML.
var (
	usernameRE     = regexp.MustCompile(`reddit\.com/(?:user|u)/([^/?#]+)`)
	postKarmaRE    = regexp.MustCompile(`(\d+(?:,\d+)?)\s*(?:post|link)\s*karma`)
	commentKarmaRE = regexp.MustCompile(`(\d+(?:,\d+)?)\s*comment\s*karma`)
	cakeDayRE      = regexp.MustCompile(`(?i)redditor since.*?(\d{4})`)
	subredditRE    = regexp.MustCompile(`data-subreddit="([^"]+)"`)
	postRE         = regexp.MustCompile(
		`(?s)<div[^>]+class="[^"]*\blink\b[^"]*"[^>]+data-subreddit="([^"]+)"[^>]*>` +
			`.*?<time[^>]+datetime="([^"]+)"[^>]*>` +
			`.*?<a[^>]+class="[^"]*\btitle\b[^"]*"[^>]*>([^<]+)</a>`)
	commentRE = regexp.MustCompile(
		`(?s)<div[^>]+class="[^"]*\bcomment\b[^"]*"[^>]+data-subreddit="([^"]+)"[^>]*>` +
			`.*?<time[^>]+datetime="([^"]+)"[^>]*>` +
			`.*?<div class="md"[^>]*>(.*?)</div>`)
	htmlTagRE         = regexp.MustCompile(`<[^>]*>`)
	genericSubreddits = map[string]bool{
		"AskReddit": true, "pics": true, "funny": true, "movies": true,
		"gaming": true, "worldnews": true, "news": true, "todayilearned": true,
		"nottheonion": true, "explainlikeimfive": true, "mildlyinteresting": true,
		"DIY": true, "videos": true, "OldSchoolCool": true, "TwoXChromosomes": true,
		"tifu": true, "Music": true, "books": true, "LifeProTips": true,
		"dataisbeautiful": true, "aww": true, "science": true, "space": true,
		"Showerthoughts": true, "askscience": true, "Jokes": true, "IAmA": true,
		"Futurology": true, "sports": true, "UpliftingNews": true, "food": true,
		"nosleep": true, "creepy": true, "history": true, "gifs": true,
		"InternetIsBeautiful": true, "GetMotivated": true, "gadgets": true,
		"announcements": true, "WritingPrompts": true, "philosophy": true,
		"Documentaries": true, "EarthPorn": true, "photoshopbattles": true,
		"listentothis": true, "blog": true, "all": true, "popular": true,
		"reddit": true,
	}
)

// platformInfo implements profile.Platform for Reddit.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Reddit user profile URL.
func Match(url string) bool {
	lower := strings.ToLower(url)
	return strings.Contains(lower, "reddit.com/user/") ||
		strings.Contains(lower, "reddit.com/u/")
}

// AuthRequired returns false because Reddit profiles are public.
func AuthRequired() bool { return false }

// Client handles Reddit requests.
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

// New creates a Reddit client.
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

// Fetch retrieves a Reddit profile.
func (c *Client) Fetch(ctx context.Context, url string) (*profile.Profile, error) {
	user := extractUsername(url)
	if user == "" {
		return nil, fmt.Errorf("could not extract username from: %s", url)
	}

	// Normalize to old.reddit.com for simpler HTML parsing
	url = fmt.Sprintf("https://old.reddit.com/user/%s", user)
	c.logger.InfoContext(ctx, "fetching reddit profile", "url", url, "username", user)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(string(body), url, user)
}

func parseProfile(html, url, user string) (*profile.Profile, error) {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: user,
		Fields:   make(map[string]string),
	}

	// Extract name from title
	p.PageTitle = htmlutil.Title(html)
	if p.PageTitle != "" {
		name := strings.TrimPrefix(p.PageTitle, "overview for ")
		if idx := strings.Index(name, " - Reddit"); idx != -1 {
			name = strings.TrimSpace(name[:idx])
		}
		p.DisplayName = name
	}
	if p.DisplayName == "" {
		p.DisplayName = user
	}

	// Extract karma
	if m := postKarmaRE.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["post_karma"] = strings.ReplaceAll(m[1], ",", "")
	}
	if m := commentKarmaRE.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["comment_karma"] = strings.ReplaceAll(m[1], ",", "")
	}

	// Extract cake day (account creation date)
	if m := cakeDayRE.FindStringSubmatch(html); len(m) > 1 {
		p.CreatedAt = m[1]
	}

	// Extract posts and comments with subreddit context
	p.Posts = extractPosts(html, 50)

	// Extract unique subreddits from posts
	if subs := extractSubreddits(html); len(subs) > 0 {
		p.Fields["subreddits"] = strings.Join(subs, ", ")
	}

	// Extract social links, filtering out Reddit's own
	for _, link := range htmlutil.SocialLinks(html) {
		if !strings.Contains(link, "reddit.com") &&
			!strings.Contains(link, "redd.it") &&
			!strings.Contains(link, "redditblog.com") {
			p.SocialLinks = append(p.SocialLinks, link)
		}
	}

	return p, nil
}

func extractUsername(url string) string {
	if m := usernameRE.FindStringSubmatch(url); len(m) > 1 {
		return m[1]
	}
	return ""
}

// extractSubreddits extracts subreddit names from Reddit profile HTML.
func extractSubreddits(html string) []string {
	matches := subredditRE.FindAllStringSubmatch(html, -1)
	seen := make(map[string]bool)
	var subs []string

	for _, m := range matches {
		if len(m) <= 1 {
			continue
		}
		sub := m[1]
		if strings.HasPrefix(sub, "u_") || genericSubreddits[sub] || seen[sub] {
			continue
		}
		seen[sub] = true
		subs = append(subs, sub)
	}

	if len(subs) > 10 {
		subs = subs[:10]
	}
	return subs
}

// extractPosts extracts posts and comments from Reddit profile HTML.
func extractPosts(html string, limit int) []profile.Post {
	var posts []profile.Post

	// Extract submitted posts
	for _, m := range postRE.FindAllStringSubmatch(html, -1) {
		if len(m) <= 3 || len(posts) >= limit {
			continue
		}
		title := strings.TrimSpace(stripHTML(m[3]))
		if title == "" {
			continue
		}
		posts = append(posts, profile.Post{
			Type:     profile.PostTypePost,
			Title:    title,
			Category: m[1],
			Date:     formatDate(m[2]),
		})
	}

	// Extract comments
	for _, m := range commentRE.FindAllStringSubmatch(html, -1) {
		if len(m) <= 3 || len(posts) >= limit {
			continue
		}
		text := strings.TrimSpace(stripHTML(m[3]))
		if len(text) < 20 {
			continue
		}
		if strings.Contains(text, "archived post") || strings.Contains(text, "automatically archived") {
			continue
		}
		if len(text) > 200 {
			text = text[:200] + "..."
		}
		posts = append(posts, profile.Post{
			Type:     profile.PostTypeComment,
			Content:  text,
			Category: m[1],
			Date:     formatDate(m[2]),
		})
	}

	return posts
}

// formatDate converts ISO 8601 datetime to YYYY-MM-DD.
func formatDate(dt string) string {
	if dt == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, dt)
	if err != nil {
		if t, err = time.Parse("2006-01-02T15:04:05", dt); err != nil {
			return dt
		}
	}
	return t.Format("2006-01-02")
}

// stripHTML removes HTML tags and decodes entities.
func stripHTML(s string) string {
	s = htmlTagRE.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	return s
}
