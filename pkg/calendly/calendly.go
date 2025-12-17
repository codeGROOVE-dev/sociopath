// Package calendly fetches Calendly user profile data.
package calendly

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "calendly"

// platformInfo implements profile.Platform for Calendly.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeScheduling }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)calendly\.com/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Calendly profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "calendly.com/") {
		return false
	}
	// Skip known non-profile paths
	nonProfiles := []string{"/app/", "/signup", "/login", "/integrations", "/features", "/pricing", "/about"}
	for _, path := range nonProfiles {
		if strings.Contains(lower, path) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Calendly profiles are public.
func AuthRequired() bool { return false }

// Client handles Calendly requests.
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

// New creates a Calendly client.
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

// Fetch retrieves a Calendly profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)

	c.logger.InfoContext(ctx, "fetching calendly profile", "url", urlStr, "username", username)

	// Normalize URL to profile root (strip event type paths like /30min)
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

	// Extract name from og:title - format: "Liz Fong-Jones"
	ogTitle := htmlutil.OGTag(content, "og:title")
	if ogTitle != "" {
		p.DisplayName = strings.TrimSpace(ogTitle)
	}

	// Extract avatar from og:image
	ogImage := htmlutil.OGTag(content, "og:image")
	if ogImage != "" {
		p.AvatarURL = ogImage
	}

	// Extract bio from og:description
	ogDesc := htmlutil.OGTag(content, "og:description")
	if ogDesc != "" && !strings.Contains(ogDesc, "scheduling page") {
		p.Bio = ogDesc
	}

	// Extract social links from page
	for _, link := range htmlutil.SocialLinks(content) {
		if !strings.Contains(link, "calendly.com/") {
			p.SocialLinks = append(p.SocialLinks, link)
		}
	}

	return p
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func normalizeProfileURL(urlStr, username string) string {
	// Strip event type paths to get the profile root
	if username != "" {
		return "https://calendly.com/" + username
	}
	return urlStr
}
