// Package gitverse fetches GitVerse.ru profile data.
// GitVerse is a Russian Git hosting platform similar to GitHub/GitLab.
package gitverse

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

const platform = "gitverse"

// platformInfo implements profile.Platform for GitVerse.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a GitVerse profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "gitverse.ru/") {
		return false
	}
	// Exclude non-profile paths
	if strings.Contains(lower, "/explore") || strings.Contains(lower, "/features") ||
		strings.Contains(lower, "/signin") || strings.Contains(lower, "/signup") {
		return false
	}
	// Must be a simple path (username or username/repo)
	parts := strings.Split(strings.TrimPrefix(lower, "https://"), "/")
	return len(parts) >= 2
}

// AuthRequired returns false because GitVerse profiles are public.
func AuthRequired() bool { return false }

// Client handles GitVerse requests.
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

// New creates a GitVerse client.
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

// Fetch retrieves a GitVerse profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching gitverse profile", "url", urlStr, "username", username)

	// Normalize to profile URL
	profileURL := fmt.Sprintf("https://gitverse.ru/%s", username)

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

// parseProfile extracts profile data from GitVerse HTML.
func parseProfile(data []byte, urlStr, username string) (*profile.Profile, error) {
	content := string(data)

	// Check if profile exists
	if strings.Contains(content, "404") && strings.Contains(content, "Страница не найдена") {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
		Groups:        []string{},
	}

	// Extract display name
	nameRe := regexp.MustCompile(`<span[^>]*class="[^"]*user-profile-name[^"]*"[^>]*>([^<]+)</span>`)
	if m := nameRe.FindStringSubmatch(content); len(m) > 1 {
		p.DisplayName = strings.TrimSpace(m[1])
	}

	// Extract bio/description
	bioRe := regexp.MustCompile(`<div[^>]*class="[^"]*user-profile-bio[^"]*"[^>]*>([^<]+)</div>`)
	if m := bioRe.FindStringSubmatch(content); len(m) > 1 {
		p.Bio = strings.TrimSpace(m[1])
	}

	// Extract location
	locationRe := regexp.MustCompile(`<div[^>]*class="[^"]*user-profile-location[^"]*"[^>]*>\s*<[^>]+>\s*([^<]+)</div>`)
	if m := locationRe.FindStringSubmatch(content); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`<img[^>]+class="[^"]*ui avatar[^"]*"[^>]+src="([^"]+)"`)
	if m := avatarRe.FindStringSubmatch(content); len(m) > 1 {
		avatar := m[1]
		if !strings.HasPrefix(avatar, "http") {
			avatar = "https://gitverse.ru" + avatar
		}
		p.AvatarURL = avatar
	}

	// Extract website
	websiteRe := regexp.MustCompile(`<a[^>]+href="(https?://[^"]+)"[^>]*rel="nofollow"[^>]*>`)
	if m := websiteRe.FindStringSubmatch(content); len(m) > 1 {
		p.Website = m[1]
	}

	// Extract created date
	joinedRe := regexp.MustCompile(`Joined on ([^<]+)<`)
	if m := joinedRe.FindStringSubmatch(content); len(m) > 1 {
		p.CreatedAt = strings.TrimSpace(m[1])
	}

	// Extract follower/following counts
	followersRe := regexp.MustCompile(`<a[^>]+href="/[^"]+\?tab=followers"[^>]*>([^<]+)</a>`)
	if m := followersRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["followers"] = strings.TrimSpace(m[1])
	}

	followingRe := regexp.MustCompile(`<a[^>]+href="/[^"]+\?tab=following"[^>]*>([^<]+)</a>`)
	if m := followingRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["following"] = strings.TrimSpace(m[1])
	}

	// Extract organizations
	orgRe := regexp.MustCompile(`<a[^>]+href="/([^"]+)"[^>]*title="([^"]+)"[^>]*class="[^"]*ui avatar[^"]*"`)
	orgMatches := orgRe.FindAllStringSubmatch(content, -1)
	for _, m := range orgMatches {
		if len(m) > 2 {
			orgName := strings.TrimSpace(m[1])
			if orgName != username && !strings.Contains(orgName, "/") {
				p.Groups = append(p.Groups, orgName)
			}
		}
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract repositories as posts
	p.Posts = extractRepos(content, username)

	return p, nil
}

// extractRepos extracts public repositories from profile.
func extractRepos(content, username string) []profile.Post {
	var posts []profile.Post

	// Look for repository entries
	repoRe := regexp.MustCompile(`<a[^>]+href="/` + username + `/([^"]+)"[^>]*class="[^"]*repo[^"]*"[^>]*>([^<]+)</a>`)
	matches := repoRe.FindAllStringSubmatch(content, 20)

	for _, m := range matches {
		if len(m) > 2 {
			repoName := strings.TrimSpace(m[1])
			title := strings.TrimSpace(m[2])
			if title == "" {
				title = repoName
			}

			posts = append(posts, profile.Post{
				Type:  profile.PostTypeRepository,
				Title: title,
				URL:   fmt.Sprintf("https://gitverse.ru/%s/%s", username, repoName),
			})
		}
	}

	return posts
}

// extractUsername extracts username from GitVerse URL.
func extractUsername(urlStr string) string {
	if idx := strings.Index(urlStr, "gitverse.ru/"); idx != -1 {
		username := urlStr[idx+len("gitverse.ru/"):]
		// Take only the first path component (username)
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}
	return ""
}
