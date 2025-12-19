// Package vcru fetches VC.ru (Venture Capital Russia) user profile data.
// VC.ru is a Russian tech/startup blogging and community platform.
package vcru

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
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

const platform = "vcru"

// platformInfo implements profile.Platform for VC.ru.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a VC.ru profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "vc.ru/") {
		return false
	}
	// Match vc.ru/u/username or vc.ru/username patterns
	// Exclude article paths and other non-profile URLs
	if strings.Contains(lower, "/news") || strings.Contains(lower, "/education") ||
		strings.Contains(lower, "/dev") || strings.Contains(lower, "/marketing") {
		return false
	}
	return true
}

// AuthRequired returns false because VC.ru profiles are public.
func AuthRequired() bool { return false }

// Client handles VC.ru requests.
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

// New creates a VC.ru client.
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

// Fetch retrieves a VC.ru profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching vcru profile", "url", urlStr, "username", username)

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

// parseProfile extracts profile data from VC.ru HTML.
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

	// Extract from JSON initial state (VC.ru embeds data in window.__INITIAL_STATE__)
	initialStateRe := regexp.MustCompile(`window\.__INITIAL_STATE__\s*=\s*({.+?});`)
	if m := initialStateRe.FindStringSubmatch(content); len(m) > 1 {
		var state struct {
			User struct {
				ID          int    `json:"id"`
				Name        string `json:"name"`
				Avatar      string `json:"avatar_url"`
				Description string `json:"description"`
				Karma       int    `json:"karma"`
				Counters    struct {
					Entries     int `json:"entries"`
					Comments    int `json:"comments"`
					Subscribers int `json:"subscribers"`
				} `json:"counters"`
				Created string `json:"created"`
			} `json:"user"`
		}

		if err := json.Unmarshal([]byte(m[1]), &state); err == nil {
			if state.User.ID > 0 {
				p.DisplayName = state.User.Name
				p.Bio = state.User.Description
				p.AvatarURL = state.User.Avatar
				p.CreatedAt = state.User.Created

				if state.User.Karma > 0 {
					p.Fields["karma"] = strconv.Itoa(state.User.Karma)
				}
				if state.User.Counters.Entries > 0 {
					p.Fields["entries"] = strconv.Itoa(state.User.Counters.Entries)
				}
				if state.User.Counters.Comments > 0 {
					p.Fields["comments"] = strconv.Itoa(state.User.Counters.Comments)
				}
				if state.User.Counters.Subscribers > 0 {
					p.Fields["subscribers"] = strconv.Itoa(state.User.Counters.Subscribers)
				}
			}
		}
	}

	// Fallback: extract display name from title
	if p.DisplayName == "" {
		titleRe := regexp.MustCompile(`<title>([^<]+)(?:\s*—\s*VC\.ru)?</title>`)
		if m := titleRe.FindStringSubmatch(content); len(m) > 1 {
			p.DisplayName = strings.TrimSpace(m[1])
		}
	}

	// Extract avatar if not found
	if p.AvatarURL == "" {
		avatarRe := regexp.MustCompile(`"avatar_url":"([^"]+)"`)
		if m := avatarRe.FindStringSubmatch(content); len(m) > 1 {
			p.AvatarURL = m[1]
		}
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract recent posts
	p.Posts = extractPosts(content)

	return p, nil
}

// extractPosts extracts recent articles/posts from profile.
func extractPosts(content string) []profile.Post {
	var posts []profile.Post

	// Look for entries in the feed
	entryRe := regexp.MustCompile(`"title":"([^"]+)"[^}]*"url":"([^"]+)"[^}]*"date":"([^"]+)"`)
	matches := entryRe.FindAllStringSubmatch(content, 20)

	for _, m := range matches {
		if len(m) > 3 {
			title := htmlUnescape(m[1])
			url := htmlUnescape(m[2])
			if !strings.HasPrefix(url, "http") {
				url = "https://vc.ru" + url
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

// extractUsername extracts username from VC.ru URL.
func extractUsername(urlStr string) string {
	// Handle vc.ru/u/123-username or vc.ru/username
	if idx := strings.Index(urlStr, "vc.ru/u/"); idx != -1 {
		username := urlStr[idx+len("vc.ru/u/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		// Remove ID prefix if present (e.g., "123-username" -> "username")
		if dashIdx := strings.Index(username, "-"); dashIdx != -1 {
			username = username[dashIdx+1:]
		}
		return strings.TrimSpace(username)
	}

	if idx := strings.Index(urlStr, "vc.ru/"); idx != -1 {
		username := urlStr[idx+len("vc.ru/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}

	return ""
}

// htmlUnescape unescapes common HTML entities in JSON strings.
func htmlUnescape(s string) string {
	s = strings.ReplaceAll(s, `\u0022`, `"`)
	s = strings.ReplaceAll(s, `\u0026`, `&`)
	s = strings.ReplaceAll(s, `\u003c`, `<`)
	s = strings.ReplaceAll(s, `\u003e`, `>`)
	s = strings.ReplaceAll(s, `\u0027`, `'`)
	s = strings.ReplaceAll(s, `\/`, `/`)
	return s
}
