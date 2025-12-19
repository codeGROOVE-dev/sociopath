// Package qnahabr fetches qna.habr.com (Habr Q&A) profile data.
// QnA Habr is the Q&A section of Habr, formerly known as Toster.ru.
package qnahabr

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

const platform = "qnahabr"

// platformInfo implements profile.Platform for QnA Habr.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a QnA Habr profile URL or toster.ru (redirects to qna.habr).
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	// Match both qna.habr.com and toster.ru (which redirects)
	if strings.Contains(lower, "qna.habr.com/") || strings.Contains(lower, "toster.ru/") {
		// Profile URLs contain /user/ or /users/
		return strings.Contains(lower, "/user/") || strings.Contains(lower, "/users/")
	}
	return false
}

// AuthRequired returns false because QnA Habr profiles are public.
func AuthRequired() bool { return false }

// Client handles QnA Habr requests.
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

// New creates a QnA Habr client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout:       5 * time.Second,
			CheckRedirect: nil, // Follow redirects (toster.ru -> qna.habr.com)
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves a QnA Habr profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching qnahabr profile", "url", urlStr, "username", username)

	// Handle both toster.ru (redirects) and qna.habr.com URLs
	var profileURL string
	if strings.Contains(urlStr, "toster.ru") {
		profileURL = strings.Replace(urlStr, "toster.ru", "qna.habr.com", 1)
	} else {
		profileURL = urlStr
	}

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

// parseProfile extracts profile data from QnA Habr HTML.
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

	// Extract display name
	nameRe := regexp.MustCompile(`<h1[^>]*class="[^"]*tm-user-title[^"]*"[^>]*>([^<]+)</h1>`)
	if m := nameRe.FindStringSubmatch(content); len(m) > 1 {
		p.DisplayName = strings.TrimSpace(m[1])
	}

	// Fallback: from page title
	if p.DisplayName == "" {
		titleRe := regexp.MustCompile(`<title>([^—<]+)(?:\s*—\s*)?`)
		if m := titleRe.FindStringSubmatch(content); len(m) > 1 {
			p.DisplayName = strings.TrimSpace(m[1])
		}
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`<img[^>]+class="[^"]*tm-user-image__pic[^"]*"[^>]+src="([^"]+)"`)
	if m := avatarRe.FindStringSubmatch(content); len(m) > 1 {
		avatar := m[1]
		if strings.HasPrefix(avatar, "//") {
			avatar = "https:" + avatar
		} else if !strings.HasPrefix(avatar, "http") {
			avatar = "https://qna.habr.com" + avatar
		}
		p.AvatarURL = avatar
	}

	// Extract bio/about
	bioRe := regexp.MustCompile(`<div[^>]*class="[^"]*user-summary__about[^"]*"[^>]*>(?:<[^>]+>)?([^<]+)`)
	if m := bioRe.FindStringSubmatch(content); len(m) > 1 {
		p.Bio = strings.TrimSpace(m[1])
	}

	// Extract location
	locationRe := regexp.MustCompile(`<div[^>]*class="[^"]*user-summary__location[^"]*"[^>]*>(?:<[^>]+>)?([^<]+)`)
	if m := locationRe.FindStringSubmatch(content); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract karma/rating
	karmaRe := regexp.MustCompile(`<span[^>]*class="[^"]*tm-karma__value[^"]*"[^>]*>([^<]+)</span>`)
	if m := karmaRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["karma"] = strings.TrimSpace(m[1])
	}

	// Extract question count
	questionsRe := regexp.MustCompile(`(\d+)\s+вопрос`)
	if m := questionsRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["questions"] = m[1]
	}

	// Extract answer count
	answersRe := regexp.MustCompile(`(\d+)\s+ответ`)
	if m := answersRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["answers"] = m[1]
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract recent questions/answers as posts
	p.Posts = extractPosts(content)

	return p, nil
}

// extractPosts extracts recent questions and answers.
func extractPosts(content string) []profile.Post {
	var posts []profile.Post

	// Look for question entries
	questionRe := regexp.MustCompile(`<a[^>]+href="(/q/\d+)"[^>]*class="[^"]*qa-title[^"]*"[^>]*>([^<]+)</a>`)
	matches := questionRe.FindAllStringSubmatch(content, 20)

	for _, m := range matches {
		if len(m) > 2 {
			title := strings.TrimSpace(m[2])
			url := m[1]
			if !strings.HasPrefix(url, "http") {
				url = "https://qna.habr.com" + url
			}

			posts = append(posts, profile.Post{
				Type:  profile.PostTypeQuestion,
				Title: title,
				URL:   url,
			})
		}
	}

	return posts
}

// extractUsername extracts username from QnA Habr or Toster URL.
func extractUsername(urlStr string) string {
	// Handle qna.habr.com/user/username or toster.ru/user/username
	if idx := strings.Index(urlStr, "/user/"); idx != -1 {
		username := urlStr[idx+len("/user/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}

	// Handle /users/ variant
	if idx := strings.Index(urlStr, "/users/"); idx != -1 {
		username := urlStr[idx+len("/users/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}

	return ""
}
