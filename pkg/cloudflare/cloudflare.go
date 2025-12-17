// Package cloudflare fetches Cloudflare Community user profile data.
package cloudflare

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

const platform = "cloudflare"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)community\.cloudflare\.com/u/([a-zA-Z0-9_.-]+)`)

// Match returns true if the URL is a Cloudflare Community profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "community.cloudflare.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Cloudflare Community profiles are public.
func AuthRequired() bool { return false }

// Client handles Cloudflare requests.
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

// New creates a Cloudflare client.
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
	User *apiUser `json:"user"`
}

type apiUser struct {
	Username       string `json:"username"`
	Name           string `json:"name"`
	AvatarTemplate string `json:"avatar_template"`
	Title          string `json:"title"`
	Location       string `json:"location"`
	Website        string `json:"website"`
	WebsiteName    string `json:"website_name"`
	Bio            string `json:"bio_raw"`
	CreatedAt      string `json:"created_at"`
	ID             int    `json:"id"`
	TrustLevel     int    `json:"trust_level"`
	BadgeCount     int    `json:"badge_count"`
	TimeRead       int    `json:"time_read"`
	PostCount      int    `json:"post_count"`
	TopicsEntered  int    `json:"topics_entered"`
	LikesGiven     int    `json:"likes_given"`
	LikesReceived  int    `json:"likes_received"`
	DaysVisited    int    `json:"days_visited"`
}

// Fetch retrieves a Cloudflare Community profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching cloudflare profile", "url", urlStr, "username", username)

	apiURL := "https://community.cloudflare.com/u/" + username + "/card.json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp apiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse cloudflare response: %w", err)
	}

	if resp.User == nil || resp.User.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(resp.User, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Username,
		Fields:   make(map[string]string),
	}

	if data.Name != "" {
		p.DisplayName = data.Name
	} else {
		p.DisplayName = data.Username
	}

	// Build avatar URL from template
	if data.AvatarTemplate != "" {
		avatarURL := strings.Replace(data.AvatarTemplate, "{size}", "240", 1)
		if !strings.HasPrefix(avatarURL, "http") {
			avatarURL = "https://community.cloudflare.com" + avatarURL
		}
		p.AvatarURL = avatarURL
	}

	if data.Location != "" {
		p.Location = data.Location
	}

	if data.Website != "" {
		p.Website = data.Website
	}

	if data.Bio != "" {
		p.Bio = data.Bio
	}

	if data.Title != "" {
		p.Fields["title"] = data.Title
	}

	if data.TrustLevel > 0 {
		p.Fields["trust_level"] = strconv.Itoa(data.TrustLevel)
	}

	if data.BadgeCount > 0 {
		p.Fields["badges"] = strconv.Itoa(data.BadgeCount)
	}

	if data.PostCount > 0 {
		p.Fields["posts"] = strconv.Itoa(data.PostCount)
	}

	if data.LikesReceived > 0 {
		p.Fields["likes_received"] = strconv.Itoa(data.LikesReceived)
	}

	if data.DaysVisited > 0 {
		p.Fields["days_visited"] = strconv.Itoa(data.DaysVisited)
	}

	if data.CreatedAt != "" {
		p.CreatedAt = data.CreatedAt
	}

	if data.ID > 0 {
		p.DatabaseID = strconv.Itoa(data.ID)
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
