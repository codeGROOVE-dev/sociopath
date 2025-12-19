// Package developpez fetches Developpez.com/net profile data.
// Developpez is the largest French-language developer community forum.
package developpez

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

const platform = "developpez"

// platformInfo implements profile.Platform for Developpez.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Developpez profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	// Match developpez.com/user/profil/ or developpez.net/forums/
	if strings.Contains(lower, "developpez.com/") || strings.Contains(lower, "developpez.net/") {
		return strings.Contains(lower, "/user/profil/") || strings.Contains(lower, "/membres/") ||
			strings.Contains(lower, "/member") || strings.Contains(lower, "/blogs/")
	}
	return false
}

// AuthRequired returns false because Developpez profiles are public.
func AuthRequired() bool { return false }

// Client handles Developpez requests.
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

// New creates a Developpez client.
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

// Fetch retrieves a Developpez profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching developpez profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
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

	return parseProfile(body, urlStr, username)
}

// parseProfile extracts profile data from Developpez HTML.
func parseProfile(data []byte, urlStr, username string) (*profile.Profile, error) {
	content := string(data)

	// Check if profile exists
	if strings.Contains(content, "utilisateur introuvable") || strings.Contains(content, "User not found") {
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

	// Fallback: from page title
	if p.DisplayName == "" {
		titleRe := regexp.MustCompile(`<title>(?:Profil de |Profile of )?([^<\-|]+)`)
		if m := titleRe.FindStringSubmatch(content); len(m) > 1 {
			p.DisplayName = strings.TrimSpace(m[1])
		}
	}

	// Extract avatar from forum format
	avatarRe := regexp.MustCompile(`image\.php\?u=(\d+)`)
	if m := avatarRe.FindStringSubmatch(content); len(m) > 1 {
		p.AvatarURL = fmt.Sprintf("https://www.developpez.net/forums/image.php?u=%s", m[1])
	}

	// Extract location
	locationRe := regexp.MustCompile(`(?i)(?:Localisation|Location)[^:]*:\s*(?:<[^>]+>)?([^<\n]+)`)
	if m := locationRe.FindStringSubmatch(content); len(m) > 1 {
		location := strings.TrimSpace(m[1])
		// Remove flag emojis and clean up
		location = regexp.MustCompile(`[\x{1F1E6}-\x{1F1FF}]+`).ReplaceAllString(location, "")
		p.Location = strings.TrimSpace(location)
	}

	// Extract registration date
	registeredRe := regexp.MustCompile(`Inscrit le ([0-9]{1,2} [a-zéû]+ [0-9]{4})|Registered on ([A-Za-z]+ [0-9]{1,2}, [0-9]{4})`)
	if m := registeredRe.FindStringSubmatch(content); len(m) > 1 {
		if m[1] != "" {
			p.CreatedAt = m[1]
		} else if m[2] != "" {
			p.CreatedAt = m[2]
		}
	}

	// Extract message/post count
	messagesRe := regexp.MustCompile(`(?i)(?:Messages?|Posts?)[^:]*:\s*(?:<[^>]+>)?(\d+)`)
	if m := messagesRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["messages"] = m[1]
	}

	// Extract points
	pointsRe := regexp.MustCompile(`Points[^:]*:\s*(?:<[^>]+>)?(\d+)`)
	if m := pointsRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["points"] = m[1]
	}

	// Extract status/rank
	statusRe := regexp.MustCompile(`(?:Membre|Member|Candidat au Club)[^<]*`)
	if m := statusRe.FindStringSubmatch(content); len(m) > 0 {
		status := strings.TrimSpace(m[0])
		if status != "" && !strings.Contains(status, ":") {
			p.Fields["status"] = status
		}
	}

	// Extract bio/signature
	bioRe := regexp.MustCompile(`(?i)<div[^>]*(?:class="[^"]*signature[^"]*"|class="[^"]*bio[^"]*")[^>]*>(?:<[^>]+>)?([^<]+)`)
	if m := bioRe.FindStringSubmatch(content); len(m) > 1 {
		p.Bio = strings.TrimSpace(m[1])
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract recent forum posts/threads
	p.Posts = extractPosts(content)

	return p, nil
}

// extractPosts extracts recent forum posts or blog entries.
func extractPosts(content string) []profile.Post {
	var posts []profile.Post

	// Look for forum thread links
	threadRe := regexp.MustCompile(`<a[^>]+href="(https?://www\.developpez\.net/forums/[^"]+)"[^>]*>([^<]+)</a>`)
	matches := threadRe.FindAllStringSubmatch(content, 20)

	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) <= 2 {
			continue
		}
		url := m[1]
		title := strings.TrimSpace(m[2])

		// Skip navigation and metadata links
		if len(title) < 5 || strings.Contains(url, "/inscription") ||
			strings.Contains(url, "/search") || strings.Contains(url, "/image.php") {
			continue
		}

		// Deduplicate
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

// extractUsername extracts username from Developpez URL.
func extractUsername(urlStr string) string {
	// Handle developpez.com/user/profil/USER_ID/username
	if idx := strings.Index(urlStr, "/user/profil/"); idx != -1 {
		remainder := urlStr[idx+len("/user/profil/"):]
		parts := strings.Split(remainder, "/")
		if len(parts) >= 2 {
			// Return username (second part after user ID)
			username := parts[1]
			username = strings.Split(username, "?")[0]
			return strings.TrimSpace(username)
		}
	}

	// Handle forum member URLs
	patterns := []string{
		"/membres/",
		"/member/",
		"/blogs/",
	}

	for _, pattern := range patterns {
		idx := strings.Index(urlStr, pattern)
		if idx == -1 {
			continue
		}
		username := urlStr[idx+len(pattern):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		username = strings.Split(username, "-")[0] // Remove ID suffix if present
		return strings.TrimSpace(username)
	}

	return ""
}
