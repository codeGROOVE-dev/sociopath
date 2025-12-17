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
	"strconv"
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
	Karma            int    `json:"karma"`
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

	// Fetch recent stories and get total count
	stories, totalStories := c.fetchRecentStories(ctx, username, 15)
	p.Posts = stories
	if totalStories > 0 {
		p.Fields["stories"] = strconv.Itoa(totalStories)
	}

	return p, nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	prof := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    data.Username,
		DisplayName: data.Username,
		Fields:      make(map[string]string),
	}

	// Parse creation date
	if data.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, data.CreatedAt); err == nil {
			prof.CreatedAt = t.Format("2006-01-02")
		}
	}

	// Avatar URL
	if data.AvatarURL != "" {
		avatarURL := data.AvatarURL
		if strings.HasPrefix(avatarURL, "/") {
			avatarURL = "https://lobste.rs" + avatarURL
		}
		prof.AvatarURL = avatarURL
	}

	// GitHub username - valuable for identity correlation
	if data.GitHubUsername != "" {
		githubURL := "https://github.com/" + data.GitHubUsername
		prof.Fields["github"] = githubURL
		prof.SocialLinks = append(prof.SocialLinks, githubURL)
	}

	// Mastodon username
	if data.MastodonUsername != "" {
		prof.Fields["mastodon"] = data.MastodonUsername
	}

	// Invited by (shows community connection)
	if data.InvitedByUser != "" {
		prof.Fields["invited_by"] = data.InvitedByUser
	}

	// Karma
	if data.Karma > 0 {
		prof.Fields["karma"] = strconv.Itoa(data.Karma)
	}

	// Parse about section (HTML)
	if data.About != "" {
		// Decode HTML and strip tags for bio
		bio := html.UnescapeString(data.About)
		bio = stripHTMLTags(bio)
		bio = strings.TrimSpace(bio)
		if bio != "" {
			prof.Bio = bio
		}

		// Extract additional links from about section
		aboutLinks := htmlutil.SocialLinks(data.About)
		seen := make(map[string]bool)
		for _, link := range aboutLinks {
			// Clean up any trailing HTML artifacts
			link = strings.TrimRight(link, "<>\"'")
			// Skip duplicates and GitHub links we already captured
			if seen[link] {
				continue
			}
			seen[link] = true
			if data.GitHubUsername != "" && strings.Contains(link, "github.com/"+data.GitHubUsername) {
				continue
			}
			prof.SocialLinks = append(prof.SocialLinks, link)
		}

		// Extract email if present
		emails := htmlutil.EmailAddresses(data.About)
		if len(emails) > 0 {
			prof.Fields["email"] = emails[0]
		}
	}

	return prof
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
// Returns the posts and total story count.
func (c *Client) fetchRecentStories(ctx context.Context, username string, maxItems int) (posts []profile.Post, totalCount int) {
	storiesURL := fmt.Sprintf("https://lobste.rs/~%s/stories.json", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, storiesURL, http.NoBody)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to create stories request", "error", err)
		return nil, 0
	}
	req.Header.Set("User-Agent", "sociopath/1.0 (social profile aggregator)")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to fetch stories", "error", err)
		return nil, 0
	}

	var stories []apiStory
	if err := json.Unmarshal(body, &stories); err != nil {
		c.logger.DebugContext(ctx, "failed to parse stories response", "error", err)
		return nil, 0
	}

	totalCount = len(stories)

	if len(stories) > maxItems {
		stories = stories[:maxItems]
	}

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

	return posts, totalCount
}
