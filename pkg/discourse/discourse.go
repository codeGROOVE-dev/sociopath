// Package discourse fetches Discourse forum profile data from various Linux communities.
// This unified implementation supports multiple Discourse instances including NixOS, KDE,
// Pop!_OS, EndeavourOS, Ubuntu, and openSUSE forums.
package discourse

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "discourse"

// Known Discourse forum domains (Linux-focused communities).
var discourseCommunities = map[string]string{
	"discourse.nixos.org":      "NixOS",
	"discuss.kde.org":          "KDE",
	"community.pop-os.org":     "Pop!_OS",
	"forum.endeavouros.com":    "EndeavourOS",
	"discourse.ubuntu.com":     "Ubuntu",
	"forums.opensuse.org":      "openSUSE",
	"discourse.ros.org":        "ROS", // Robot Operating System
	"community.frame.work":     "Framework",
	"forum.manjaro.org":        "Manjaro",
	"discourse.gnome.org":      "GNOME",
	"forum.arduino.cc":         "Arduino",
	"community.home-assistant.io": "Home Assistant",
}

// platformInfo implements profile.Platform for Discourse forums.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.RegisterWithFetcher(platformInfo{}, fetchProfile) }

var usernamePattern = regexp.MustCompile(`/u/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a supported Discourse profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)

	// Check if URL contains /u/ pattern (Discourse user profile path)
	if !strings.Contains(lower, "/u/") {
		return false
	}

	// Extract domain
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	domain := strings.ToLower(u.Hostname())
	_, known := discourseCommunities[domain]
	return known
}

// AuthRequired returns false because Discourse forums are public.
func AuthRequired() bool { return false }

// Client handles Discourse requests.
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

// New creates a Discourse client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
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

// discourseUserResponse represents the Discourse API user response.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type discourseUserResponse struct {
	User discourseUser `json:"user"`
}

// discourseUser represents a Discourse user.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type discourseUser struct {
	ID               int    `json:"id"`
	Username         string `json:"username"`
	Name             string `json:"name"`
	AvatarTemplate   string `json:"avatar_template"`
	Bio              string `json:"bio_raw"`
	Location         string `json:"location"`
	Website          string `json:"website"`
	ProfileViewCount int    `json:"profile_view_count"`
	CreatedAt        string `json:"created_at"`
	LastSeenAt       string `json:"last_seen_at"`
	TrustLevel       int    `json:"trust_level"`
	Admin            bool   `json:"admin"`
	Moderator        bool   `json:"moderator"`
	BadgeCount       int    `json:"badge_count"`
}

// Fetch retrieves a Discourse profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	// Extract domain from URL
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}
	domain := u.Hostname()

	c.logger.InfoContext(ctx, "fetching discourse profile", "url", urlStr, "username", username, "domain", domain)

	// Use Discourse API
	apiURL := fmt.Sprintf("https://%s/u/%s.json", domain, username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp discourseUserResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse discourse response: %w", err)
	}

	if resp.User.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(&resp.User, urlStr, domain)
}

func parseProfile(data *discourseUser, profileURL, domain string) (*profile.Profile, error) {
	p := &profile.Profile{
		Platform:    platform,
		URL:         profileURL,
		Username:    data.Username,
		DisplayName: data.Name,
		Bio:         data.Bio,
		Location:    data.Location,
		CreatedAt:   data.CreatedAt,
		UpdatedAt:   data.LastSeenAt,
		Fields:      make(map[string]string),
	}

	// Store community name
	if communityName, ok := discourseCommunities[domain]; ok {
		p.Fields["community"] = communityName
	}

	// Construct avatar URL from template
	if data.AvatarTemplate != "" {
		// Discourse avatar templates use {size} placeholder
		avatarURL := strings.ReplaceAll(data.AvatarTemplate, "{size}", "240")
		if !strings.HasPrefix(avatarURL, "http") {
			avatarURL = "https://" + domain + avatarURL
		}
		p.AvatarURL = avatarURL
	}

	if data.Website != "" {
		p.Website = data.Website
		p.SocialLinks = append(p.SocialLinks, data.Website)
	}

	if p.DisplayName == "" {
		p.DisplayName = p.Username
	}

	// Store additional metadata
	if data.TrustLevel > 0 {
		p.Fields["trust_level"] = fmt.Sprintf("%d", data.TrustLevel)
	}
	if data.Admin {
		p.Fields["admin"] = "true"
	}
	if data.Moderator {
		p.Fields["moderator"] = "true"
	}
	if data.BadgeCount > 0 {
		p.Fields["badge_count"] = fmt.Sprintf("%d", data.BadgeCount)
	}
	if data.ProfileViewCount > 0 {
		p.Fields["profile_views"] = fmt.Sprintf("%d", data.ProfileViewCount)
	}

	return p, nil
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// fetchProfile is the FetchFunc wrapper for profile registration.
func fetchProfile(ctx context.Context, url string, cfg *profile.FetcherConfig) (*profile.Profile, error) {
	var opts []Option
	if cfg != nil {
		if cfg.Logger != nil {
			opts = append(opts, WithLogger(cfg.Logger))
		}
		if c, ok := cfg.Cache.(httpcache.Cacher); ok {
			opts = append(opts, WithHTTPCache(c))
		}
	}

	client, err := New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return client.Fetch(ctx, url)
}
