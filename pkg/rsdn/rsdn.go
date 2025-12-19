// Package rsdn fetches RSDN.org (Russian Software Developer Network) profile data.
// RSDN is a Russian developer community forum.
package rsdn

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

const platform = "rsdn"

// platformInfo implements profile.Platform for RSDN.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is an RSDN profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "rsdn.org/") && !strings.Contains(lower, "rsdn.ru/") {
		return false
	}
	// Common profile patterns
	return strings.Contains(lower, "/member") || strings.Contains(lower, "/user") ||
		strings.Contains(lower, "/profile")
}

// AuthRequired returns false because RSDN profiles are public.
func AuthRequired() bool { return false }

// Client handles RSDN requests.
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

// New creates an RSDN client.
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

// Fetch retrieves an RSDN profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching rsdn profile", "url", urlStr, "username", username)

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

// parseProfile extracts profile data from RSDN HTML.
func parseProfile(data []byte, urlStr, username string) (*profile.Profile, error) {
	content := string(data)

	// Check if profile exists
	if strings.Contains(content, "User not found") || strings.Contains(content, "Пользователь не найден") {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Extract display name
	nameRe := regexp.MustCompile(`<h1[^>]*class="[^"]*username[^"]*"[^>]*>([^<]+)</h1>`)
	if m := nameRe.FindStringSubmatch(content); len(m) > 1 {
		p.DisplayName = strings.TrimSpace(m[1])
	}

	// Fallback: generic h1
	if p.DisplayName == "" {
		nameRe = regexp.MustCompile(`<h1[^>]*>([^<]+)</h1>`)
		if m := nameRe.FindStringSubmatch(content); len(m) > 1 {
			p.DisplayName = strings.TrimSpace(m[1])
		}
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`<img[^>]+(?:class="[^"]*avatar[^"]*"|alt="[^"]*avatar[^"]*")[^>]+src="([^"]+)"`)
	if m := avatarRe.FindStringSubmatch(content); len(m) > 1 {
		avatar := m[1]
		if strings.HasPrefix(avatar, "//") {
			avatar = "https:" + avatar
		} else if !strings.HasPrefix(avatar, "http") {
			avatar = "https://rsdn.org" + avatar
		}
		p.AvatarURL = avatar
	}

	// Extract bio/signature
	bioRe := regexp.MustCompile(`(?i)<div[^>]*class="[^"]*(?:signature|bio|about)[^"]*"[^>]*>([^<]+)</div>`)
	if m := bioRe.FindStringSubmatch(content); len(m) > 1 {
		p.Bio = strings.TrimSpace(m[1])
	}

	// Extract location
	locationRe := regexp.MustCompile(`(?i)(?:Location|Откуда|From)[^:]*:\s*(?:<[^>]+>)?([^<]+)`)
	if m := locationRe.FindStringSubmatch(content); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract post count
	postsRe := regexp.MustCompile(`(?i)(?:Posts|Messages|Сообщений)[^:]*:\s*(?:<[^>]+>)?(\d+)`)
	if m := postsRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["posts"] = m[1]
	}

	// Extract registration date
	registeredRe := regexp.MustCompile(`(?i)(?:Registered|Joined|Зарегистрирован)[^:]*:\s*(?:<[^>]+>)?([^<]+)`)
	if m := registeredRe.FindStringSubmatch(content); len(m) > 1 {
		p.CreatedAt = strings.TrimSpace(m[1])
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract recent forum posts/threads
	p.Posts = extractPosts(content)

	return p, nil
}

// extractPosts extracts recent forum posts or threads.
func extractPosts(content string) []profile.Post {
	var posts []profile.Post

	// Look for forum thread/post entries
	threadRe := regexp.MustCompile(`<a[^>]+href="(/forum/[^"]+)"[^>]*>([^<]+)</a>`)
	matches := threadRe.FindAllStringSubmatch(content, 20)

	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) <= 2 {
			continue
		}
		url := m[1]
		if !strings.HasPrefix(url, "http") {
			url = "https://rsdn.org" + url
		}

		// Deduplicate
		if seen[url] {
			continue
		}
		seen[url] = true

		title := strings.TrimSpace(m[2])
		if title == "" || len(title) < 3 {
			continue
		}

		posts = append(posts, profile.Post{
			Type:  profile.PostTypeComment,
			Title: title,
			URL:   url,
		})

		// Limit to 10 posts
		if len(posts) >= 10 {
			break
		}
	}

	return posts
}

// extractUsername extracts username from RSDN URL.
func extractUsername(urlStr string) string {
	// Handle various profile URL patterns
	patterns := []string{
		"/member/",
		"/members/",
		"/user/",
		"/users/",
		"/profile/",
		"/profiles/",
	}

	for _, pattern := range patterns {
		idx := strings.Index(urlStr, pattern)
		if idx == -1 {
			continue
		}
		username := urlStr[idx+len(pattern):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		username = strings.Split(username, "&")[0]
		return strings.TrimSpace(username)
	}

	return ""
}
