// Package replit fetches Replit profile data.
package replit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "replit"

// platformInfo implements profile.Platform for Replit.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypePackage }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)replit\.com/@([a-zA-Z][a-zA-Z0-9_-]{0,38})`)

// Match returns true if the URL is a Replit profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "replit.com/@") {
		return false
	}
	// Exclude repl URLs (have additional path after username)
	// e.g., replit.com/@user/repl-name
	match := usernamePattern.FindStringSubmatch(urlStr)
	if len(match) < 2 {
		return false
	}
	// Check if there's additional path after the username
	afterMatch := urlStr[strings.Index(strings.ToLower(urlStr), "@"+strings.ToLower(match[1]))+len(match[1])+1:]
	if strings.Contains(afterMatch, "/") && !strings.HasPrefix(afterMatch, "?") {
		// Has a path after username - likely a repl URL
		trimmed := strings.TrimPrefix(afterMatch, "/")
		if trimmed != "" && !strings.HasPrefix(trimmed, "?") {
			return false
		}
	}
	return true
}

// AuthRequired returns false because Replit profiles are public.
func AuthRequired() bool { return false }

// Client handles Replit requests.
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

// New creates a Replit client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

// nextData represents the __NEXT_DATA__ JSON structure.
type nextData struct {
	Props struct {
		ApolloState map[string]json.RawMessage `json:"apolloState"`
	} `json:"props"`
}

// userData represents a Replit user from Apollo state.
type userData struct {
	Username string `json:"username"`
	FullName string `json:"fullName"`
	Bio      string `json:"bio"`
	Location string `json:"location"`
	Image    string `json:"image"`
	URL      string `json:"url"`
	Socials  []struct {
		Ref string `json:"__ref"`
	} `json:"socials"`
}

// socialData represents a social link from Apollo state.
type socialData struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

// Pattern to extract __NEXT_DATA__ JSON.
var nextDataPattern = regexp.MustCompile(`__NEXT_DATA__"[^>]*>(\{.+?\})</script>`)

// Fetch retrieves a Replit profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching replit profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://replit.com/@%s", username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return c.parseProfile(ctx, string(body), profileURL)
}

func (c *Client) parseProfile(ctx context.Context, html, profileURL string) (*profile.Profile, error) {
	// Extract __NEXT_DATA__ JSON
	match := nextDataPattern.FindStringSubmatch(html)
	if len(match) < 2 {
		return nil, errors.New("could not find __NEXT_DATA__ in page")
	}

	var nd nextData
	if err := json.Unmarshal([]byte(match[1]), &nd); err != nil {
		return nil, fmt.Errorf("failed to parse __NEXT_DATA__: %w", err)
	}

	// Find user data in Apollo state
	var user *userData
	var socials []socialData

	for key, raw := range nd.Props.ApolloState {
		if strings.HasPrefix(key, "User:") {
			var u userData
			if err := json.Unmarshal(raw, &u); err == nil && u.Username != "" {
				user = &u
			}
		} else if strings.HasPrefix(key, "UserSocial:") {
			var s socialData
			if err := json.Unmarshal(raw, &s); err == nil && s.URL != "" {
				socials = append(socials, s)
			}
		}
	}

	if user == nil {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:  platform,
		URL:       profileURL,
		Username:  user.Username,
		Name:      user.FullName,
		Bio:       user.Bio,
		AvatarURL: user.Image,
		Fields:    make(map[string]string),
	}

	if user.Location != "" {
		p.Location = user.Location
	}

	// Add social links
	for _, s := range socials {
		p.SocialLinks = append(p.SocialLinks, s.URL)
		c.logger.InfoContext(ctx, "discovered social link from replit",
			"platform", s.Type, "link", s.URL, "source", "replit")
	}

	return p, nil
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		username := matches[1]
		// Remove query parameters
		if idx := strings.Index(username, "?"); idx > 0 {
			username = username[:idx]
		}
		return username
	}
	return ""
}
