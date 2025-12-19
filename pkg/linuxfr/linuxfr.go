// Package linuxfr fetches LinuxFr.org profile data.
// LinuxFr is a major French open-source and libre software community site.
package linuxfr

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

const platform = "linuxfr"

// platformInfo implements profile.Platform for LinuxFr.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a LinuxFr profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "linuxfr.org/") {
		return false
	}
	// Profile URLs are linuxfr.org/users/username
	return strings.Contains(lower, "/users/")
}

// AuthRequired returns false because LinuxFr profiles are public.
func AuthRequired() bool { return false }

// Client handles LinuxFr requests.
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

// New creates a LinuxFr client.
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

// Fetch retrieves a LinuxFr profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching linuxfr profile", "url", urlStr, "username", username)

	// Normalize to user profile URL
	profileURL := fmt.Sprintf("https://linuxfr.org/users/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "fr-FR,fr;q=0.9,en;q=0.8")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, profileURL, username)
}

// parseProfile extracts profile data from LinuxFr HTML.
func parseProfile(data []byte, urlStr, username string) (*profile.Profile, error) {
	content := string(data)

	// Check if profile exists
	if strings.Contains(content, "Utilisateur introuvable") || strings.Contains(content, "User not found") {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Extract display name from h1
	nameRe := regexp.MustCompile(`<h1[^>]*>([^<]+)</h1>`)
	if m := nameRe.FindStringSubmatch(content); len(m) > 1 {
		p.DisplayName = strings.TrimSpace(m[1])
	}

	// Extract registration date
	registeredRe := regexp.MustCompile(`Inscrit le ([0-9]{2}/[0-9]{2}/[0-9]{4})|Member since ([0-9]{2}/[0-9]{2}/[0-9]{4})`)
	if m := registeredRe.FindStringSubmatch(content); len(m) > 1 {
		if m[1] != "" {
			p.CreatedAt = m[1]
		} else if m[2] != "" {
			p.CreatedAt = m[2]
		}
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	if m := avatarRe.FindStringSubmatch(content); len(m) > 1 {
		avatar := m[1]
		if strings.HasPrefix(avatar, "//") {
			avatar = "https:" + avatar
		} else if !strings.HasPrefix(avatar, "http") {
			avatar = "https://linuxfr.org" + avatar
		}
		p.AvatarURL = avatar
	}

	// Extract personal website
	websiteRe := regexp.MustCompile(`Site personnel[^:]*:\s*<a[^>]+href="([^"]+)"`)
	if m := websiteRe.FindStringSubmatch(content); len(m) > 1 {
		p.Website = m[1]
	}

	// Extract contribution count
	contribRe := regexp.MustCompile(`(\d+)\s+(?:contenus|contents?)`)
	if m := contribRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["contributions"] = m[1]
	}

	// Extract karma/score
	karmaRe := regexp.MustCompile(`Karma[^:]*:\s*(?:<[^>]+>)?(\d+)`)
	if m := karmaRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["karma"] = m[1]
	}

	// Extract bio from meta description
	bioRe := regexp.MustCompile(`<meta[^>]+name="description"[^>]+content="([^"]+)"`)
	if m := bioRe.FindStringSubmatch(content); len(m) > 1 {
		bio := strings.TrimSpace(m[1])
		// Clean up description
		if !strings.Contains(bio, "LinuxFr.org") {
			p.Bio = bio
		}
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract recent journal entries and posts
	p.Posts = extractPosts(content, username)

	return p, nil
}

// extractPosts extracts recent journal entries (articles) and forum posts.
func extractPosts(content, username string) []profile.Post {
	var posts []profile.Post

	// Look for journal entries (journaux)
	journalRe := regexp.MustCompile(`<a[^>]+href="(/users/` + username + `/journaux/[^"]+)"[^>]*>([^<]+)</a>`)
	matches := journalRe.FindAllStringSubmatch(content, 20)

	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) <= 2 {
			continue
		}
		url := "https://linuxfr.org" + m[1]
		title := strings.TrimSpace(m[2])

		if len(title) < 3 {
			continue
		}

		if seen[url] {
			continue
		}
		seen[url] = true

		posts = append(posts, profile.Post{
			Type:  profile.PostTypeArticle,
			Title: title,
			URL:   url,
		})

		if len(posts) >= 10 {
			break
		}
	}

	// Also look for general content links
	if len(posts) < 10 {
		contentRe := regexp.MustCompile(`<a[^>]+href="(https://linuxfr\.org/(?:news|forums|wiki)/[^"]+)"[^>]*>([^<]+)</a>`)
		contentMatches := contentRe.FindAllStringSubmatch(content, 20)

		for _, m := range contentMatches {
			if len(m) <= 2 || len(posts) >= 10 {
				break
			}
			url := m[1]
			title := strings.TrimSpace(m[2])

			if len(title) < 5 || seen[url] {
				continue
			}
			seen[url] = true

			postType := profile.PostTypeArticle
			if strings.Contains(url, "/forums/") {
				postType = profile.PostTypeComment
			}

			posts = append(posts, profile.Post{
				Type:  postType,
				Title: title,
				URL:   url,
			})
		}
	}

	return posts
}

// extractUsername extracts username from LinuxFr URL.
func extractUsername(urlStr string) string {
	// Handle linuxfr.org/users/username
	if idx := strings.Index(urlStr, "/users/"); idx != -1 {
		username := urlStr[idx+len("/users/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}
	return ""
}
