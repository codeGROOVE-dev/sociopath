// Package pikabu fetches Pikabu.ru profile data.
// Pikabu is a Russian social news aggregation and discussion platform similar to Reddit.
package pikabu

import (
	"context"
	"crypto/tls"
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

const platform = "pikabu"

// platformInfo implements profile.Platform for Pikabu.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Pikabu profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "pikabu.ru/") {
		return false
	}
	// Profile URLs are pikabu.ru/@username
	return strings.Contains(lower, "/@") || strings.Contains(lower, "/profile/")
}

// AuthRequired returns false because Pikabu profiles are public.
func AuthRequired() bool { return false }

// Client handles Pikabu requests.
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

// New creates a Pikabu client.
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

// Fetch retrieves a Pikabu profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching pikabu profile", "url", urlStr, "username", username)

	// Normalize to @username format
	profileURL := fmt.Sprintf("https://pikabu.ru/@%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, profileURL, username)
}

// parseProfile extracts profile data from Pikabu HTML.
func parseProfile(data []byte, urlStr, username string) (*profile.Profile, error) {
	content := string(data)

	// Check if profile exists
	if strings.Contains(content, "Пользователь не найден") || strings.Contains(content, "User not found") {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Extract from JSON-LD structured data
	jsonLDRe := regexp.MustCompile(`<script type="application/ld\+json">(\{[^<]+\})</script>`)
	if m := jsonLDRe.FindStringSubmatch(content); len(m) > 1 {
		var data struct {
			Type        string `json:"@type"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Image       string `json:"image"`
			URL         string `json:"url"`
		}

		if err := json.Unmarshal([]byte(m[1]), &data); err == nil {
			if data.Type == "ProfilePage" || data.Type == "Person" {
				p.DisplayName = data.Name
				p.Bio = data.Description
				p.AvatarURL = data.Image
			}
		}
	}

	// Extract karma/rating
	karmaRe := regexp.MustCompile(`"rating"\s*:\s*(\d+)`)
	if m := karmaRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["karma"] = m[1]
	}

	// Extract post count
	postsRe := regexp.MustCompile(`"posts_count"\s*:\s*(\d+)`)
	if m := postsRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["posts"] = m[1]
	}

	// Extract comment count
	commentsRe := regexp.MustCompile(`"comments_count"\s*:\s*(\d+)`)
	if m := commentsRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["comments"] = m[1]
	}

	// Extract subscriber count
	subscribersRe := regexp.MustCompile(`"subscribers"\s*:\s*(\d+)`)
	if m := subscribersRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["subscribers"] = m[1]
	}

	// Extract registration date
	registeredRe := regexp.MustCompile(`Registered\s+(\d+)\s+years?\s+ago|зарегистрирован\s+(\d+)\s+(?:год|года|лет)\s+назад`)
	if m := registeredRe.FindStringSubmatch(content); len(m) > 1 {
		years := m[1]
		if years == "" {
			years = m[2]
		}
		p.Fields["years_registered"] = years
	}

	// Extract avatar if not found
	if p.AvatarURL == "" {
		avatarRe := regexp.MustCompile(`<img[^>]+class="[^"]*profile__avatar[^"]*"[^>]+src="([^"]+)"`)
		if m := avatarRe.FindStringSubmatch(content); len(m) > 1 {
			p.AvatarURL = m[1]
		}
	}

	// Extract display name if not found
	if p.DisplayName == "" {
		nameRe := regexp.MustCompile(`<h1[^>]*class="[^"]*profile__username[^"]*"[^>]*>@?([^<]+)</h1>`)
		if m := nameRe.FindStringSubmatch(content); len(m) > 1 {
			p.DisplayName = strings.TrimSpace(m[1])
		}
	}

	// Extract bio if not found
	if p.Bio == "" {
		bioRe := regexp.MustCompile(`<div[^>]*class="[^"]*profile__description[^"]*"[^>]*>([^<]+)</div>`)
		if m := bioRe.FindStringSubmatch(content); len(m) > 1 {
			p.Bio = strings.TrimSpace(m[1])
		}
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract recent posts
	p.Posts = extractPosts(content, username)

	return p, nil
}

// extractPosts extracts recent posts/stories from profile.
func extractPosts(content, _ string) []profile.Post {
	var posts []profile.Post

	// Look for story entries
	storyRe := regexp.MustCompile(`<article[^>]+data-story-id="(\d+)"[^>]*>(?:[\s\S]*?)<a[^>]+href="(/story/[^"]+)"[^>]*>([^<]+)</a>`)
	matches := storyRe.FindAllStringSubmatch(content, 20)

	for _, m := range matches {
		if len(m) > 3 {
			title := strings.TrimSpace(m[3])
			url := m[2]
			if !strings.HasPrefix(url, "http") {
				url = "https://pikabu.ru" + url
			}

			posts = append(posts, profile.Post{
				Type:  profile.PostTypeArticle,
				Title: title,
				URL:   url,
			})
		}
	}

	return posts
}

// extractUsername extracts username from Pikabu URL.
func extractUsername(urlStr string) string {
	// Handle pikabu.ru/@username
	if idx := strings.Index(urlStr, "/@"); idx != -1 {
		username := urlStr[idx+2:]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}

	// Handle pikabu.ru/profile/username
	if idx := strings.Index(urlStr, "/profile/"); idx != -1 {
		username := urlStr[idx+len("/profile/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}

	return ""
}
