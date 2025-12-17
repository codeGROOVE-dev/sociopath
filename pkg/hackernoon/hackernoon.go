// Package hackernoon fetches HackerNoon user profile data.
package hackernoon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "hackernoon"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)hackernoon\.com/u/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a HackerNoon profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "hackernoon.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because HackerNoon profiles are public.
func AuthRequired() bool { return false }

// Client handles HackerNoon requests.
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

// New creates a HackerNoon client.
func New(_ context.Context, opts ...Option) (*Client, error) {
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

type apiResponse struct {
	PageProps struct {
		User *apiUser `json:"user"`
	} `json:"pageProps"`
}

type apiUser struct {
	Handle       string `json:"handle"`
	DisplayName  string `json:"displayName"`
	About        string `json:"about"`
	Avatar       string `json:"avatar"`
	Location     string `json:"location"`
	Website      string `json:"website"`
	Twitter      string `json:"twitter"`
	GitHub       string `json:"github"`
	LinkedIn     string `json:"linkedin"`
	StoriesCount int    `json:"storiesCount"`
	Followers    int    `json:"followers"`
}

// Fetch retrieves a HackerNoon profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching hackernoon profile", "url", urlStr, "username", username)

	// Use the Next.js data endpoint
	apiURL := "https://hackernoon.com/_next/data/foL6JC7ro2FEEMD-gMKgQ/u/" + username + ".json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		// Try HTML fallback
		return c.fetchHTML(ctx, username, urlStr)
	}

	var resp apiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		// Try HTML fallback
		return c.fetchHTML(ctx, username, urlStr)
	}

	if resp.PageProps.User == nil {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(resp.PageProps.User, urlStr), nil
}

func (c *Client) fetchHTML(ctx context.Context, username, urlStr string) (*profile.Profile, error) {
	profileURL := "https://hackernoon.com/u/" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	content := string(body)

	if strings.Contains(content, "Page not found") || strings.Contains(content, "404") {
		return nil, profile.ErrProfileNotFound
	}

	return parseHTMLProfile(content, username, urlStr), nil
}

var (
	displayNameHTML = regexp.MustCompile(`(?i)<h1[^>]*>([^<]+)</h1>`)
	avatarHTML      = regexp.MustCompile(`(?i)<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	bioHTML         = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*bio[^"]*"[^>]*>([^<]+)</div>`)
	locationHTML    = regexp.MustCompile(`(?i)<span[^>]*class="[^"]*location[^"]*"[^>]*>([^<]+)</span>`)
)

func parseHTMLProfile(html, username, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    username,
		DisplayName: username,
		Fields:      make(map[string]string),
	}

	if m := displayNameHTML.FindStringSubmatch(html); len(m) > 1 {
		p.DisplayName = strings.TrimSpace(m[1])
	}

	if m := avatarHTML.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	if m := bioHTML.FindStringSubmatch(html); len(m) > 1 {
		p.Bio = strings.TrimSpace(m[1])
	}

	if m := locationHTML.FindStringSubmatch(html); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	return p
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Handle,
		Fields:   make(map[string]string),
	}

	if data.DisplayName != "" {
		p.DisplayName = data.DisplayName
	} else {
		p.DisplayName = data.Handle
	}

	if data.Avatar != "" {
		p.AvatarURL = data.Avatar
	}

	if data.About != "" {
		p.Bio = data.About
	}

	if data.Location != "" {
		p.Location = data.Location
	}

	if data.Website != "" {
		p.Website = data.Website
	}

	if data.StoriesCount > 0 {
		p.Fields["stories"] = strconv.Itoa(data.StoriesCount)
	}

	if data.Followers > 0 {
		p.Fields["followers"] = strconv.Itoa(data.Followers)
	}

	// Social links
	if data.Twitter != "" {
		p.SocialLinks = append(p.SocialLinks, "https://twitter.com/"+data.Twitter)
	}
	if data.GitHub != "" {
		p.SocialLinks = append(p.SocialLinks, "https://github.com/"+data.GitHub)
	}
	if data.LinkedIn != "" {
		p.SocialLinks = append(p.SocialLinks, "https://linkedin.com/in/"+data.LinkedIn)
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
