// Package dailydev fetches Daily.dev user profile data.
package dailydev

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

const platform = "dailydev"

// platformInfo implements profile.Platform for Daily.dev.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)(?:app\.)?daily\.dev/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Daily.dev profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "daily.dev/") {
		return false
	}
	// Exclude non-profile paths
	excludePaths := []string{"/posts/", "/sources/", "/tags/", "/settings/", "/categories/", "/search", "/about", "/privacy", "/terms"}
	for _, p := range excludePaths {
		if strings.Contains(lower, p) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Daily.dev profiles are public.
func AuthRequired() bool { return false }

// Client handles Daily.dev requests.
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

// New creates a Daily.dev client.
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

// nextData represents the __NEXT_DATA__ JSON structure.
type nextData struct {
	Props struct {
		PageProps struct {
			User *userData `json:"user"`
		} `json:"pageProps"`
	} `json:"props"`
}

// userData represents a Daily.dev user from Next.js data.
type userData struct {
	ID            string         `json:"id"`
	Username      string         `json:"username"`
	Name          string         `json:"name"`
	Image         string         `json:"image"`
	Bio           string         `json:"bio"`
	Company       string         `json:"company"`
	Title         string         `json:"title"`
	Portfolio     string         `json:"portfolio"`
	Permalink     string         `json:"permalink"`
	Reputation    float64        `json:"reputation"`
	GitHub        string         `json:"github"`
	Twitter       string         `json:"twitter"`
	Hashnode      string         `json:"hashnode"`
	Cover         string         `json:"cover"`
	ReadmeHTML    string         `json:"readmeHtml"`
	CreatedAt     string         `json:"createdAt"`
	UserStats     *userStats     `json:"userStats"`
	Socials       []socialLink   `json:"socialLinks"`
	ContentPreference map[string]any `json:"contentPreference"`
}

// userStats represents user statistics.
type userStats struct {
	Posts           int `json:"posts"`
	Comments        int `json:"comments"`
	PostViews       int `json:"postViews"`
	PostUpvotes     int `json:"postUpvotes"`
	CommentUpvotes  int `json:"commentUpvotes"`
}

// socialLink represents a social media link.
type socialLink struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Pattern to extract __NEXT_DATA__ JSON.
var nextDataPattern = regexp.MustCompile(`__NEXT_DATA__"[^>]*>(\{.+?\})</script>`)

// Fetch retrieves a Daily.dev profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching dailydev profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://app.daily.dev/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return c.parseProfile(ctx, string(body), profileURL, username)
}

func (c *Client) parseProfile(_ context.Context, html, profileURL, username string) (*profile.Profile, error) {
	if htmlutil.IsNotFound(html) {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Try to extract __NEXT_DATA__ JSON
	match := nextDataPattern.FindStringSubmatch(html)
	if len(match) >= 2 {
		var nd nextData
		if err := json.Unmarshal([]byte(match[1]), &nd); err == nil && nd.Props.PageProps.User != nil {
			c.extractFromJSON(nd.Props.PageProps.User, p)
		}
	}

	// Fallback to HTML parsing for any missing fields
	c.extractFromHTML(html, p)

	// If no unique data found, or data is generic, it might be a generic page
	if (p.DisplayName == "" || htmlutil.IsGenericTitle(p.DisplayName)) && p.Bio == "" && p.AvatarURL == "" {
		return nil, profile.ErrProfileNotFound
	}

	// Extract social links
	if len(p.SocialLinks) == 0 {
		p.SocialLinks = htmlutil.RelMeLinks(html)
		if len(p.SocialLinks) == 0 {
			p.SocialLinks = htmlutil.SocialLinks(html)
		}
	}

	return p, nil
}

func (c *Client) extractFromJSON(user *userData, p *profile.Profile) {
	if user.Username != "" {
		p.Username = user.Username
	}
	if user.Name != "" {
		p.DisplayName = user.Name
	}
	if user.Image != "" {
		p.AvatarURL = user.Image
	}
	if user.Bio != "" {
		p.Bio = strings.TrimSpace(user.Bio)
	}
	if user.Company != "" {
		p.Fields["company"] = user.Company
	}
	if user.Title != "" {
		p.Fields["title"] = user.Title
	}
	if user.Portfolio != "" {
		p.Website = user.Portfolio
	}
	if user.CreatedAt != "" {
		p.CreatedAt = user.CreatedAt
	}
	if user.ReadmeHTML != "" {
		// Store README content
		p.Content = user.ReadmeHTML
	}

	// Extract social links
	if user.GitHub != "" {
		github := normalizeGitHubURL(user.GitHub)
		p.Fields["github"] = github
		p.SocialLinks = append(p.SocialLinks, github)
	}
	if user.Twitter != "" {
		twitter := normalizeTwitterURL(user.Twitter)
		p.Fields["twitter"] = twitter
		p.SocialLinks = append(p.SocialLinks, twitter)
	}
	if user.Hashnode != "" {
		hashnode := normalizeHashnodeURL(user.Hashnode)
		p.Fields["hashnode"] = hashnode
		p.SocialLinks = append(p.SocialLinks, hashnode)
	}

	// Extract additional social links
	for _, social := range user.Socials {
		if social.URL != "" && !contains(p.SocialLinks, social.URL) {
			p.SocialLinks = append(p.SocialLinks, social.URL)
		}
	}

	// Extract stats
	if user.Reputation > 0 {
		p.Fields["reputation"] = fmt.Sprintf("%.0f", user.Reputation)
	}
	if user.UserStats != nil {
		if user.UserStats.Posts > 0 {
			p.Fields["posts"] = fmt.Sprintf("%d", user.UserStats.Posts)
		}
		if user.UserStats.Comments > 0 {
			p.Fields["comments"] = fmt.Sprintf("%d", user.UserStats.Comments)
		}
		if user.UserStats.PostViews > 0 {
			p.Fields["post_views"] = fmt.Sprintf("%d", user.UserStats.PostViews)
		}
		if user.UserStats.PostUpvotes > 0 {
			p.Fields["post_upvotes"] = fmt.Sprintf("%d", user.UserStats.PostUpvotes)
		}
	}
}

func (c *Client) extractFromHTML(html string, p *profile.Profile) {
	// Extract display name from title or meta tags
	if p.DisplayName == "" {
		if title := htmlutil.Title(html); title != "" {
			if htmlutil.IsGenericTitle(title) {
				return
			}
			title = strings.Split(title, " - daily.dev")[0]
			title = strings.Split(title, " | daily.dev")[0]
			title = strings.TrimSpace(title)
			if title != "" && title != p.Username && !htmlutil.IsGenericTitle(title) {
				p.DisplayName = title
			}
		}
	}

	// Extract avatar from og:image
	if p.AvatarURL == "" {
		p.AvatarURL = htmlutil.OGImage(html)
	}

	// Extract description as bio if not found
	if p.Bio == "" {
		if desc := htmlutil.Description(html); desc != "" {
			if !htmlutil.IsGenericBio(desc) {
				p.Bio = desc
			}
		}
	}
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func normalizeGitHubURL(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	if !strings.Contains(input, "://") {
		input = strings.TrimPrefix(input, "@")
		return "https://github.com/" + input
	}
	if strings.HasPrefix(input, "http://") {
		input = strings.Replace(input, "http://", "https://", 1)
	}
	return input
}

func normalizeTwitterURL(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	if !strings.Contains(input, "://") {
		input = strings.TrimPrefix(input, "@")
		return "https://twitter.com/" + input
	}
	if strings.HasPrefix(input, "http://") {
		input = strings.Replace(input, "http://", "https://", 1)
	}
	input = strings.Replace(input, "x.com/", "twitter.com/", 1)
	return input
}

func normalizeHashnodeURL(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	if !strings.Contains(input, "://") {
		return "https://hashnode.com/@" + input
	}
	if strings.HasPrefix(input, "http://") {
		input = strings.Replace(input, "http://", "https://", 1)
	}
	return input
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
