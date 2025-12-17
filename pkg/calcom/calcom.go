// Package calcom fetches Cal.com user profile data.
package calcom

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "calcom"

// platformInfo implements profile.Platform for Cal.com.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeScheduling }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Cal.com profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "://cal.com/") || strings.Contains(lower, "://www.cal.com/")
}

// AuthRequired returns false because Cal.com profiles are public.
func AuthRequired() bool { return false }

// Client handles Cal.com requests.
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

// New creates a Cal.com client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	cache := cfg.cache
	if cache == nil {
		cache = httpcache.NewNull()
	}

	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a Cal.com profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)

	c.logger.InfoContext(ctx, "fetching calcom profile", "url", urlStr, "username", username)

	// Normalize URL to profile root (strip event type paths like /coffee-chat)
	profileURL := normalizeProfileURL(urlStr, username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpcache.UserAgent)

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(body, urlStr, username), nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		DisplayName:   username,
		Fields:        make(map[string]string),
	}

	// Extract name from og:title - format: "Stephen Morgan | Cal.com"
	ogTitle := htmlutil.OGTag(content, "og:title")
	if name, _, found := strings.Cut(ogTitle, " | "); found {
		p.DisplayName = strings.TrimSpace(name)
	}

	// Extract avatar from og:image URL (encoded in query params)
	ogImage := htmlutil.OGTag(content, "og:image")
	if ogImage != "" {
		p.AvatarURL = extractAvatarFromOGImage(ogImage)
	}

	// Extract bio from meta description (more reliable than og:image title param)
	p.Bio = htmlutil.Description(content)

	// Extract event types as posts
	p.Posts = extractEventTypes(content)

	// Extract social links from page (excluding internal cal.com links)
	for _, link := range htmlutil.SocialLinks(content) {
		if !strings.Contains(link, "cal.com/") {
			p.SocialLinks = append(p.SocialLinks, link)
		}
	}

	return p
}

// extractAvatarFromOGImage extracts the avatar URL from the og:image URL.
// Cal.com encodes profile data in the OG image URL query params.
// The URL structure is: ?url=%2Fapi...%26meetingImage%3Dhttps%253A...
// So meetingImage is within another URL-encoded parameter.
func extractAvatarFromOGImage(ogImage string) string {
	// HTML unescape first (&amp; -> &)
	ogImage = strings.ReplaceAll(ogImage, "&amp;", "&")

	// First, extract the url= parameter and decode it
	urlRe := regexp.MustCompile(`url=([^&]+)`)
	urlMatch := urlRe.FindStringSubmatch(ogImage)
	if len(urlMatch) <= 1 {
		return ""
	}
	decodedURL, err := url.QueryUnescape(urlMatch[1])
	if err != nil {
		return ""
	}

	// Now look for meetingImage in the decoded URL
	re := regexp.MustCompile(`meetingImage=([^&]+)`)
	if m := re.FindStringSubmatch(decodedURL); len(m) > 1 {
		// Still need to URL-decode since it's encoded within the inner URL
		decoded, err := url.QueryUnescape(m[1])
		if err != nil {
			return ""
		}
		return decoded
	}
	return ""
}

// extractEventTypes extracts calendar event types from the page.
func extractEventTypes(content string) []profile.Post {
	var posts []profile.Post

	// Look for event type links: data-testid="event-type-link-..."
	re := regexp.MustCompile(`data-testid="event-type-link-[^"]*"[^>]*href="(/[^"]+)"[^>]*>`)
	matches := re.FindAllStringSubmatch(content, 10)
	seen := make(map[string]bool)

	for _, m := range matches {
		if len(m) <= 1 {
			continue
		}
		path := m[1]
		if seen[path] {
			continue
		}
		seen[path] = true

		// Extract event name from path (e.g., /stevemorgandev/coffee-chat -> coffee-chat)
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) >= 2 {
			eventName := parts[len(parts)-1]
			posts = append(posts, profile.Post{
				Type:  profile.PostTypeEvent,
				Title: formatEventName(eventName),
				URL:   "https://cal.com" + path,
			})
		}
	}

	// Also look for event titles in the page
	titleRe := regexp.MustCompile(`<h3[^>]*class="[^"]*text-emphasis[^"]*"[^>]*>([^<]+)</h3>`)
	titleMatches := titleRe.FindAllStringSubmatch(content, 10)
	for i, m := range titleMatches {
		if len(m) > 1 && i < len(posts) {
			posts[i].Title = strings.TrimSpace(m[1])
		}
	}

	return posts
}

// formatEventName converts a URL slug to a readable name.
func formatEventName(slug string) string {
	name := strings.ReplaceAll(slug, "-", " ")
	name = strings.Title(name) //nolint:staticcheck // simple title case is fine here
	return name
}

func extractUsername(urlStr string) string {
	re := regexp.MustCompile(`cal\.com/([^/?#]+)`)
	if m := re.FindStringSubmatch(urlStr); len(m) > 1 {
		return m[1]
	}
	return ""
}

func normalizeProfileURL(urlStr, username string) string {
	// Strip event type paths to get the profile root
	if username != "" {
		return "https://cal.com/" + username
	}
	return urlStr
}
