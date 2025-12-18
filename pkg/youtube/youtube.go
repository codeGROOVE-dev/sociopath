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

// Pre-compiled regex patterns for performance.
var (
	avatarPattern    = regexp.MustCompile(`"avatar":\{"thumbnails":\[\{"url":"([^"]+)"`)
	subPattern       = regexp.MustCompile(`([\d.]+[KMB]?)\s*(?:subscribers|Subscribers)`)
	videoCountPat    = regexp.MustCompile(`([\d,]+)\s*(?:videos|Videos)`)
	accessPattern    = regexp.MustCompile(`"accessibilityData":\{"label":"([^"]+)\s+\d+\s*(?:minutes?|seconds?|hours?)`)
	durationPattern  = regexp.MustCompile(`\s*\d+\s*(?:minutes?|seconds?|hours?).*$`)
	countryPattern   = regexp.MustCompile(`"country":"([^"]+)"`)
	extLinkPattern   = regexp.MustCompile(`"channelExternalLinkViewModel":\{"title":\{"content":"([^"]+)"\},"link":\{"content":"([^"]+)"`)
	usernamePatterns = []*regexp.Regexp{
		regexp.MustCompile(`youtube\.com/@([^/?#]+)`),
		regexp.MustCompile(`youtube\.com/c/([^/?#]+)`),
		regexp.MustCompile(`youtube\.com/user/([^/?#]+)`),
		regexp.MustCompile(`youtube\.com/channel/([^/?#]+)`),
	}
)

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

	// Also fetch the /about page which has country and social links
	aboutURL := buildAboutURL(normalizedURL)
	aboutReq, err := http.NewRequestWithContext(ctx, http.MethodGet, aboutURL, http.NoBody)
	if err == nil {
		aboutReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
		aboutReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
		if aboutBody, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, aboutReq, c.logger); err == nil {
			// Concatenate the two HTML pages for parsing
			body = append(body, aboutBody...)
		}
	}

	return parseProfile(string(body), normalizedURL)
}

// buildAboutURL constructs the /about URL for a YouTube channel.
func buildAboutURL(channelURL string) string {
	// Remove trailing slash if present
	channelURL = strings.TrimSuffix(channelURL, "/")
	// Remove any existing /about suffix
	channelURL = strings.TrimSuffix(channelURL, "/about")
	return channelURL + "/about"
}

func parseProfile(html, url string) (*profile.Profile, error) {
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: extractUsername(url),
		Fields:   make(map[string]string),
	}

	// Extract name from title or meta tags
	prof.PageTitle = htmlutil.Title(html)
	if prof.PageTitle != "" {
		// Clean up "Channel Name - YouTube" to get display name
		if idx := strings.Index(prof.PageTitle, " - YouTube"); idx != -1 {
			prof.DisplayName = strings.TrimSpace(prof.PageTitle[:idx])
		}
	}

	// Extract description (filter out default YouTube bio)
	bio := htmlutil.Description(html)
	if !isDefaultBio(bio) {
		prof.Bio = bio
	}

	// Extract avatar/channel image from og:image or channelMetadataRenderer
	if matches := avatarPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.AvatarURL = matches[1]
	}

	// Try to extract subscriber count
	if matches := subPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["subscribers"] = matches[1]
	}

	// Try to extract video count
	if matches := videoCountPat.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["videos"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract video titles from accessibility labels
	prof.Posts = extractVideoTitles(html, 50)

	// Extract country/location
	if matches := countryPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Location = matches[1]
	}

	// Extract social links from YouTube's channel external links JSON
	prof.SocialLinks = extractExternalLinks(html)

	// Also try htmlutil.SocialLinks as a fallback and merge results
	for _, link := range htmlutil.SocialLinks(html) {
		if !strings.Contains(link, "youtube.com") &&
			!strings.Contains(link, "youtu.be") &&
			!strings.Contains(link, "google.com") &&
			!slices.Contains(prof.SocialLinks, link) {
			prof.SocialLinks = append(prof.SocialLinks, link)
		}
	}

	if prof.DisplayName == "" {
		prof.DisplayName = prof.Username
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
	matches := accessPattern.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) <= 1 || len(posts) >= limit {
			continue
		}

		title := strings.TrimSpace(match[1])
		// Clean up the title - remove trailing duration info
		title = durationPattern.ReplaceAllString(title, "")
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

	for _, p := range usernamePatterns {
		if m := p.FindStringSubmatch(s); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

// extractExternalLinks extracts social/external links from YouTube's channelExternalLinkViewModel JSON.
func extractExternalLinks(html string) []string {
	var links []string
	seen := make(map[string]bool)

	matches := extLinkPattern.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		// match[1] is title (e.g., "Twitter", "Twitch")
		// match[2] is the link (e.g., "twitter.com/sidarthus89")
		link := strings.TrimSpace(match[2])
		if link == "" {
			continue
		}

		// YouTube stores links without protocol - add https://
		if !strings.HasPrefix(link, "http://") && !strings.HasPrefix(link, "https://") {
			link = "https://" + link
		}

		// Skip YouTube's own links and duplicates
		lower := strings.ToLower(link)
		if strings.Contains(lower, "youtube.com") ||
			strings.Contains(lower, "youtu.be") ||
			strings.Contains(lower, "google.com") {
			continue
		}

		if !seen[link] {
			seen[link] = true
			links = append(links, link)
		}
	}

	return links
}
