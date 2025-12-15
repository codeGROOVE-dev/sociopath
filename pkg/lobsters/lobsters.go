// Package lobsters fetches Lobste.rs user profile data.
package lobsters

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "lobsters"

// platformInfo implements profile.Platform for Lobsters.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)lobste\.rs/(?:u/|~)([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Lobste.rs user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "lobste.rs/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Lobste.rs profiles are public.
func AuthRequired() bool { return false }

// Client handles Lobste.rs requests.
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

// New creates a Lobste.rs client.
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

// apiUser represents the Lobste.rs API response.
type apiUser struct {
	Username         string `json:"username"`
	CreatedAt        string `json:"created_at"`
	About            string `json:"about"`
	AvatarURL        string `json:"avatar_url"`
	InvitedByUser    string `json:"invited_by_user"`
	GitHubUsername   string `json:"github_username"`
	MastodonUsername string `json:"mastodon_username"`
	IsAdmin          bool   `json:"is_admin"`
	IsModerator      bool   `json:"is_moderator"`
}

// apiStory represents a Lobste.rs story.
type apiStory struct { //nolint:govet // field order matches API response
	Tags         []string `json:"tags"`
	ShortID      string   `json:"short_id"`
	Title        string   `json:"title"`
	URL          string   `json:"url"`
	ShortIDURL   string   `json:"short_id_url"`
	CommentsURL  string   `json:"comments_url"`
	Score        int      `json:"score"`
	CommentCount int      `json:"comment_count"`
}

// Fetch retrieves a Lobste.rs profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching lobsters profile", "url", urlStr, "username", username)

	// Use JSON API
	apiURL := fmt.Sprintf("https://lobste.rs/~%s.json", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0 (social profile aggregator)")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var user apiUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse lobsters response: %w", err)
	}

	if user.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	p := parseProfile(&user, urlStr)

	// Fetch recent stories
	stories := c.fetchRecentStories(ctx, username, 15)
	p.Posts = stories

	return p, nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Username,
		Name:     data.Username,
		Fields:   make(map[string]string),
	}

	// Parse creation date
	if data.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, data.CreatedAt); err == nil {
			p.CreatedAt = t.Format("2006-01-02")
		}
	}

	// Avatar URL
	if data.AvatarURL != "" {
		avatarURL := data.AvatarURL
		if strings.HasPrefix(avatarURL, "/") {
			avatarURL = "https://lobste.rs" + avatarURL
		}
		p.AvatarURL = avatarURL
	}

	// GitHub username - valuable for identity correlation
	if data.GitHubUsername != "" {
		githubURL := "https://github.com/" + data.GitHubUsername
		p.Fields["github"] = githubURL
		p.SocialLinks = append(p.SocialLinks, githubURL)
	}

	// Mastodon username
	if data.MastodonUsername != "" {
		p.Fields["mastodon"] = data.MastodonUsername
	}

	// Invited by (shows community connection)
	if data.InvitedByUser != "" {
		p.Fields["invited_by"] = data.InvitedByUser
	}

	// Parse about section (HTML)
	if data.About != "" {
		// Decode HTML and strip tags for bio
		bio := html.UnescapeString(data.About)
		bio = stripHTMLTags(bio)
		bio = strings.TrimSpace(bio)
		if bio != "" {
			p.Bio = bio
		}

		// Extract additional links from about section
		aboutLinks := htmlutil.SocialLinks(data.About)
		for _, link := range aboutLinks {
			// Skip GitHub links we already captured
			if data.GitHubUsername != "" && strings.Contains(link, "github.com/"+data.GitHubUsername) {
				continue
			}
			p.SocialLinks = append(p.SocialLinks, link)
		}

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

// fetchRecentStories fetches up to maxItems recent stories from a user.
func (c *Client) fetchRecentStories(ctx context.Context, username string, maxItems int) []profile.Post {
	storiesURL := fmt.Sprintf("https://lobste.rs/~%s/stories.json", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, storiesURL, http.NoBody)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to create stories request", "error", err)
		return nil
	}
	req.Header.Set("User-Agent", "sociopath/1.0 (social profile aggregator)")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to fetch stories", "error", err)
		return nil
	}

	var stories []apiStory
	if err := json.Unmarshal(body, &stories); err != nil {
		c.logger.DebugContext(ctx, "failed to parse stories response", "error", err)
		return nil
	}

	if len(stories) > maxItems {
		stories = stories[:maxItems]
	}

	var posts []profile.Post
	for _, story := range stories {
		post := profile.Post{
			Type:  profile.PostTypePost,
			Title: story.Title,
			URL:   story.CommentsURL,
		}
		if story.URL != "" {
			post.Content = story.URL
		}
		posts = append(posts, post)
	}

	return posts
}
