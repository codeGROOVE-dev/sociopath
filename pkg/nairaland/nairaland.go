// Package nairaland fetches Nairaland profile data.
// Nairaland is Nigeria's largest online forum and community platform.
package nairaland

import (
	"context"
	"crypto/tls"
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

const platform = "nairaland"

// platformInfo implements profile.Platform for Nairaland.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Nairaland profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "nairaland.com/") {
		return false
	}
	// Profile URLs are nairaland.com/username or nairaland.com/hopto/home/id
	return !strings.Contains(lower, "/topics") && !strings.Contains(lower, "/search")
}

// AuthRequired returns false because Nairaland profiles are public.
func AuthRequired() bool { return false }

// Client handles Nairaland requests.
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

// New creates a Nairaland client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves a Nairaland profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching nairaland profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, urlStr, username)
}

// parseProfile extracts profile data from Nairaland HTML.
func parseProfile(data []byte, urlStr, username string) (*profile.Profile, error) {
	content := string(data)

	// Check if profile exists
	if strings.Contains(content, "User not found") || strings.Contains(content, "Profile not found") {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Extract display name from page
	nameRe := regexp.MustCompile(`<h1[^>]*>([^<]+)</h1>`)
	if m := nameRe.FindStringSubmatch(content); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		// Clean up "Profile of Username" format
		name = strings.TrimPrefix(name, "Profile of ")
		name = strings.TrimPrefix(name, "Profile Of ")
		p.DisplayName = name
	}

	// Fallback: from title
	if p.DisplayName == "" {
		titleRe := regexp.MustCompile(`<title>([^<\-|]+)`)
		if m := titleRe.FindStringSubmatch(content); len(m) > 1 {
			name := strings.TrimSpace(m[1])
			if !strings.Contains(name, "Nairaland") {
				p.DisplayName = name
			}
		}
	}

	// Use username as display name if nothing else found
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`<img[^>]+(?:class="[^"]*avatar[^"]*"|alt="[^"]*avatar[^"]*")[^>]+src="([^"]+)"`)
	if m := avatarRe.FindStringSubmatch(content); len(m) > 1 {
		avatar := m[1]
		if !strings.HasPrefix(avatar, "http") {
			avatar = "https://www.nairaland.com" + avatar
		}
		p.AvatarURL = avatar
	}

	// Extract bio/signature
	bioRe := regexp.MustCompile(`(?i)<div[^>]*(?:class="[^"]*signature[^"]*"|id="[^"]*signature[^"]*")[^>]*>([^<]+)</div>`)
	if m := bioRe.FindStringSubmatch(content); len(m) > 1 {
		p.Bio = strings.TrimSpace(m[1])
	}

	// Extract registration date
	registeredRe := regexp.MustCompile(`(?i)(?:Registered|Member Since|Joined)[^:]*:\s*(?:<[^>]+>)?([^<\n]+)`)
	if m := registeredRe.FindStringSubmatch(content); len(m) > 1 {
		p.CreatedAt = strings.TrimSpace(m[1])
	}

	// Extract post count
	postsRe := regexp.MustCompile(`(?i)(?:Posts?|Topics?)[^:]*:\s*(?:<[^>]+>)?(\d+)`)
	if m := postsRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["posts"] = m[1]
	}

	// Extract location
	locationRe := regexp.MustCompile(`(?i)Location[^:]*:\s*(?:<[^>]+>)?([^<\n]+)`)
	if m := locationRe.FindStringSubmatch(content); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract gender
	genderRe := regexp.MustCompile(`(?i)Gender[^:]*:\s*(?:<[^>]+>)?(Male|Female)`)
	if m := genderRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["gender"] = m[1]
	}

	// Extract rank/status
	rankRe := regexp.MustCompile(`(?i)Rank[^:]*:\s*(?:<[^>]+>)?([^<\n]+)`)
	if m := rankRe.FindStringSubmatch(content); len(m) > 1 {
		rank := strings.TrimSpace(m[1])
		if rank != "" && !strings.Contains(rank, ":") {
			p.Fields["rank"] = rank
		}
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract recent posts/topics
	p.Posts = extractPosts(content)

	return p, nil
}

// extractPosts extracts recent forum posts and topics.
func extractPosts(content string) []profile.Post {
	var posts []profile.Post

	// Look for topic/thread links
	topicRe := regexp.MustCompile(`<a[^>]+href="(https?://(?:www\.)?nairaland\.com/\d+/[^"]+)"[^>]*>([^<]+)</a>`)
	matches := topicRe.FindAllStringSubmatch(content, 20)

	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) <= 2 {
			continue
		}
		url := m[1]
		title := strings.TrimSpace(m[2])

		// Skip navigation and short titles
		if len(title) < 5 || strings.Contains(url, "/login") ||
			strings.Contains(url, "/register") || strings.Contains(url, "/search") {
			continue
		}

		if seen[url] {
			continue
		}
		seen[url] = true

		posts = append(posts, profile.Post{
			Type:  profile.PostTypeComment,
			Title: title,
			URL:   url,
		})

		if len(posts) >= 10 {
			break
		}
	}

	return posts
}

// extractUsername extracts username from Nairaland URL.
func extractUsername(urlStr string) string {
	// Handle nairaland.com/username pattern
	if idx := strings.Index(urlStr, "nairaland.com/"); idx != -1 {
		remainder := urlStr[idx+len("nairaland.com/"):]

		// Handle /hopto/home/id pattern
		if strings.HasPrefix(remainder, "hopto/home/") {
			userID := strings.TrimPrefix(remainder, "hopto/home/")
			userID = strings.Split(userID, "/")[0]
			userID = strings.Split(userID, "?")[0]
			return userID
		}

		// Handle direct username pattern
		username := strings.Split(remainder, "/")[0]
		username = strings.Split(username, "?")[0]

		// Skip if it's a section/category page
		sections := []string{"topics", "search", "news", "politics", "romance",
			"jobs", "business", "investment", "education", "programming",
			"webmasters", "technology", "science", "health", "career",
			"login", "register", "trending"}

		lower := strings.ToLower(username)
		for _, section := range sections {
			if lower == section {
				return ""
			}
		}

		return strings.TrimSpace(username)
	}
	return ""
}
