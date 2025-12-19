// Package fourprogrammers fetches 4programmers.net profile data.
// 4programmers.net is Poland's largest programming community with 130,000+ members.
package fourprogrammers

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

const platform = "4programmers"

// platformInfo implements profile.Platform for 4programmers.net.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a 4programmers.net profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "4programmers.net/") {
		return false
	}
	// Profile URLs are 4programmers.net/Profile/{id}
	return strings.Contains(lower, "/profile/")
}

// AuthRequired returns false because 4programmers.net profiles are public.
func AuthRequired() bool { return false }

// Client handles 4programmers.net requests.
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

// New creates a 4programmers.net client.
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

// Fetch retrieves a 4programmers.net profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	userID := extractUserID(urlStr)
	if userID == "" {
		return nil, fmt.Errorf("could not extract user ID from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching 4programmers profile", "url", urlStr, "user_id", userID)

	// Normalize to /Profile/{id} format
	profileURL := fmt.Sprintf("https://4programmers.net/Profile/%s", userID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, profileURL, userID)
}

// parseProfile extracts profile data from 4programmers.net HTML.
func parseProfile(data []byte, urlStr, userID string) (*profile.Profile, error) {
	content := string(data)

	// Check if profile exists
	if strings.Contains(content, "Nie znaleziono użytkownika") || strings.Contains(content, "User not found") {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Fields:        make(map[string]string),
	}

	// Store user ID
	p.Fields["user_id"] = userID

	// Extract username/display name
	usernameRe := regexp.MustCompile(`<h1[^>]*class="[^"]*media-heading[^"]*"[^>]*>([^<]+)</h1>`)
	if m := usernameRe.FindStringSubmatch(content); len(m) > 1 {
		p.Username = strings.TrimSpace(m[1])
		p.DisplayName = p.Username
	}

	// Alternative username pattern
	if p.Username == "" {
		usernameRe2 := regexp.MustCompile(`<title>([^<]+)(?:\s*-\s*4programmers\.net)?</title>`)
		if m := usernameRe2.FindStringSubmatch(content); len(m) > 1 {
			p.Username = strings.TrimSpace(m[1])
			p.DisplayName = p.Username
		}
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`<img[^>]+class="[^"]*img-thumbnail[^"]*"[^>]+src="([^"]+)"`)
	if m := avatarRe.FindStringSubmatch(content); len(m) > 1 {
		avatar := m[1]
		if strings.HasPrefix(avatar, "//") {
			avatar = "https:" + avatar
		} else if !strings.HasPrefix(avatar, "http") {
			avatar = "https://4programmers.net" + avatar
		}
		p.AvatarURL = avatar
	}

	// Extract bio/about
	bioRe := regexp.MustCompile(`<div[^>]*class="[^"]*profile-about[^"]*"[^>]*>([\s\S]*?)</div>`)
	if m := bioRe.FindStringSubmatch(content); len(m) > 1 {
		bio := m[1]
		bio = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(bio, "")
		p.Bio = strings.TrimSpace(bio)
	}

	// Extract location
	locationRe := regexp.MustCompile(`<i[^>]*class="[^"]*fa-map-marker[^"]*"[^>]*></i>\s*([^<]+)`)
	if m := locationRe.FindStringSubmatch(content); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract reputation/karma
	reputationRe := regexp.MustCompile(`(?i)<span[^>]*class="[^"]*reputation[^"]*"[^>]*>([^<]+)</span>`)
	if m := reputationRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["reputation"] = strings.TrimSpace(m[1])
	}

	// Extract registration date
	registeredRe := regexp.MustCompile(`<i[^>]*class="[^"]*fa-user-plus[^"]*"[^>]*></i>\s*([^<]+)`)
	if m := registeredRe.FindStringSubmatch(content); len(m) > 1 {
		p.CreatedAt = strings.TrimSpace(m[1])
	}

	// Extract last visit
	lastVisitRe := regexp.MustCompile(`<i[^>]*class="[^"]*fa-right-to-bracket[^"]*"[^>]*></i>\s*([^<]+)`)
	if m := lastVisitRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["last_visit"] = strings.TrimSpace(m[1])
	}

	// Extract visit count
	visitCountRe := regexp.MustCompile(`<i[^>]*class="[^"]*fa-eye[^"]*"[^>]*></i>\s*(\d+)`)
	if m := visitCountRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["visit_count"] = m[1]
	}

	// Extract skills
	skillsRe := regexp.MustCompile(`<span[^>]*class="[^"]*label[^"]*tag[^"]*"[^>]*>([^<]+)</span>`)
	matches := skillsRe.FindAllStringSubmatch(content, -1)
	var skills []string
	for _, m := range matches {
		if len(m) > 1 {
			skill := strings.TrimSpace(m[1])
			if skill != "" {
				skills = append(skills, skill)
			}
		}
	}
	if len(skills) > 0 {
		p.Fields["skills"] = strings.Join(skills, ", ")
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract recent posts
	p.Posts = extractPosts(content)

	return p, nil
}

// extractPosts extracts recent forum posts and comments.
func extractPosts(content string) []profile.Post {
	var posts []profile.Post

	// Look for forum topics
	topicRe := regexp.MustCompile(`<a[^>]+href="(/Forum/[^"]+)"[^>]*>([^<]+)</a>`)
	matches := topicRe.FindAllStringSubmatch(content, 20)

	for _, m := range matches {
		if len(m) > 2 {
			title := strings.TrimSpace(m[2])
			url := m[1]
			if !strings.HasPrefix(url, "http") {
				url = "https://4programmers.net" + url
			}

			posts = append(posts, profile.Post{
				Type:  profile.PostTypeComment,
				Title: title,
				URL:   url,
			})
		}
	}

	return posts
}

// extractUserID extracts user ID from 4programmers.net URL.
func extractUserID(urlStr string) string {
	// Handle 4programmers.net/Profile/{id}
	if idx := strings.Index(urlStr, "/Profile/"); idx != -1 {
		userID := urlStr[idx+len("/Profile/"):]
		userID = strings.Split(userID, "/")[0]
		userID = strings.Split(userID, "?")[0]
		return strings.TrimSpace(userID)
	}

	return ""
}
