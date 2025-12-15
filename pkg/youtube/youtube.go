// Package youtube fetches YouTube channel/user profile data.
package youtube

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "youtube"

// platformInfo implements profile.Platform for YouTube.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeVideo }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a YouTube channel/user URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return (strings.Contains(lower, "youtube.com/") &&
		(strings.Contains(lower, "/@") ||
			strings.Contains(lower, "/channel/") ||
			strings.Contains(lower, "/c/") ||
			strings.Contains(lower, "/user/")))
}

// AuthRequired returns false because YouTube channels are public.
func AuthRequired() bool { return false }

// Client handles YouTube requests.
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

// New creates a YouTube client.
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

// Fetch retrieves a YouTube channel profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	// Normalize URL (keep as-is since YouTube has multiple URL formats)
	normalizedURL := urlStr
	if !strings.HasPrefix(normalizedURL, "http") {
		normalizedURL = "https://www.youtube.com/" + strings.TrimPrefix(urlStr, "youtube.com/")
	}

	c.logger.InfoContext(ctx, "fetching youtube profile", "url", normalizedURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(string(body), normalizedURL)
}

func parseProfile(html, url string) (*profile.Profile, error) {
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: extractUsername(url),
		Fields:   make(map[string]string),
	}

	// Extract name from title or meta tags
	prof.Name = htmlutil.Title(html)
	if prof.Name != "" {
		// Clean up "Channel Name - YouTube"
		if idx := strings.Index(prof.Name, " - YouTube"); idx != -1 {
			prof.Name = strings.TrimSpace(prof.Name[:idx])
		}
	}

	// Extract description (filter out default YouTube bio)
	bio := htmlutil.Description(html)
	if !isDefaultBio(bio) {
		prof.Bio = bio
	}

	// Extract avatar/channel image from og:image or channelMetadataRenderer
	avatarPattern := regexp.MustCompile(`"avatar":\{"thumbnails":\[\{"url":"([^"]+)"`)
	if matches := avatarPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.AvatarURL = matches[1]
	}

	// Try to extract subscriber count
	subPattern := regexp.MustCompile(`([\d.]+[KMB]?)\s*(?:subscribers|Subscribers)`)
	if matches := subPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["subscribers"] = matches[1]
	}

	// Try to extract video count
	videoPattern := regexp.MustCompile(`([\d,]+)\s*(?:videos|Videos)`)
	if matches := videoPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["videos"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract video titles from accessibility labels
	prof.Posts = extractVideoTitles(html, 50)

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(html)

	// Filter out YouTube's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "youtube.com") &&
			!strings.Contains(link, "youtu.be") &&
			!strings.Contains(link, "google.com") {
			filtered = append(filtered, link)
		}
	}
	prof.SocialLinks = filtered

	if prof.Name == "" {
		prof.Name = prof.Username
	}

	return prof, nil
}

// isDefaultBio returns true if the bio is YouTube's default description.
func isDefaultBio(bio string) bool {
	defaultBios := []string{
		"share your videos with friends, family, and the world",
	}
	bioLower := strings.ToLower(strings.TrimSpace(bio))
	return slices.Contains(defaultBios, bioLower)
}

// extractVideoTitles extracts video titles from YouTube channel HTML.
// YouTube embeds video titles in accessibility labels with duration info.
func extractVideoTitles(html string, limit int) []profile.Post {
	var posts []profile.Post
	seen := make(map[string]bool)

	// Extract from accessibility labels - these contain actual video titles with duration
	// Pattern: "accessibilityData":{"label":"VIDEO TITLE DURATION"}
	accessPattern := regexp.MustCompile(`"accessibilityData":\{"label":"([^"]+)\s+\d+\s*(?:minutes?|seconds?|hours?)`)
	matches := accessPattern.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) <= 1 || len(posts) >= limit {
			continue
		}

		title := strings.TrimSpace(match[1])
		// Clean up the title - remove trailing duration info
		title = regexp.MustCompile(`\s*\d+\s*(?:minutes?|seconds?|hours?).*$`).ReplaceAllString(title, "")
		title = strings.TrimSuffix(title, ",")
		title = strings.TrimSpace(title)

		if title == "" || seen[title] {
			continue
		}
		seen[title] = true
		posts = append(posts, profile.Post{
			Type:  profile.PostTypeVideo,
			Title: title,
		})
	}

	return posts
}

func extractUsername(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "www.")

	// Try each YouTube URL pattern
	patterns := []string{
		`youtube\.com/@([^/?#]+)`,
		`youtube\.com/c/([^/?#]+)`,
		`youtube\.com/user/([^/?#]+)`,
		`youtube\.com/channel/([^/?#]+)`,
	}
	for _, p := range patterns {
		if m := regexp.MustCompile(p).FindStringSubmatch(s); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}
