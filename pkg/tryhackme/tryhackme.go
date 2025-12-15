// Package tryhackme fetches TryHackMe profile data.
package tryhackme

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

const platform = "tryhackme"

// platformInfo implements profile.Platform for TryHackMe.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSecurity }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)tryhackme\.com/[pr]/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a TryHackMe profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "tryhackme.com/") {
		return false
	}
	// Must be /p/ or /r/ (profile) path
	if !strings.Contains(lower, "/p/") && !strings.Contains(lower, "/r/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because TryHackMe profiles are public.
func AuthRequired() bool { return false }

// Client handles TryHackMe requests.
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

// New creates a TryHackMe client.
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

// apiResponse represents the TryHackMe API response.
type apiResponse struct {
	Status string   `json:"status"`
	Data   userData `json:"data"`
}

// userData represents a TryHackMe user from the API.
//
//nolint:govet // fieldalignment not critical for JSON parsing
type userData struct {
	Username          string `json:"username"`
	Avatar            string `json:"avatar"`
	Level             int    `json:"level"`
	Country           string `json:"country"`
	About             string `json:"about"`
	LinkedInUsername  string `json:"linkedInUsername"`
	GitHubUsername    string `json:"githubUsername"`
	TwitterUsername   string `json:"twitterUsername"`
	InstagramUsername string `json:"instagramUsername"`
	RedditUsername    string `json:"redditUsername"`
	DiscordUsername   string `json:"discordUsername"`
	PersonalWebsite   string `json:"personalWebsite"`
	Rank              int    `json:"rank"`
	BadgesNumber      int    `json:"badgesNumber"`
	CompletedRooms    int    `json:"completedRoomsNumber"`
	Streak            int    `json:"streak"`
	Subscribed        int    `json:"subscribed"`
	BadgeImageURL     string `json:"badgeImageURL"`
}

// Fetch retrieves a TryHackMe profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching tryhackme profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://tryhackme.com/api/v2/public-profile?username=%s", username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp apiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %w", err)
	}

	if resp.Status != "success" || resp.Data.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	return c.buildProfile(ctx, &resp.Data, username)
}

func (c *Client) buildProfile(ctx context.Context, user *userData, username string) (*profile.Profile, error) {
	profileURL := fmt.Sprintf("https://tryhackme.com/p/%s", username)

	prof := &profile.Profile{
		Platform:  platform,
		URL:       profileURL,
		Username:  user.Username,
		AvatarURL: user.Avatar,
		Fields:    make(map[string]string),
	}

	if user.About != "" {
		prof.Bio = strings.TrimSpace(user.About)
	}

	// Country code to location
	if user.Country != "" {
		prof.Location = strings.ToUpper(user.Country)
	}

	// Add stats as fields
	if user.Level > 0 {
		prof.Fields["level"] = strconv.Itoa(user.Level)
	}
	if user.Rank > 0 {
		prof.Fields["rank"] = strconv.Itoa(user.Rank)
	}
	if user.CompletedRooms > 0 {
		prof.Fields["completed_rooms"] = strconv.Itoa(user.CompletedRooms)
	}
	if user.BadgesNumber > 0 {
		prof.Fields["badges"] = strconv.Itoa(user.BadgesNumber)
	}
	if user.Streak > 0 {
		prof.Fields["streak"] = strconv.Itoa(user.Streak)
	}
	if user.Subscribed > 0 {
		prof.Fields["subscribed"] = "true"
	}
	if user.BadgeImageURL != "" {
		prof.Fields["badge_image"] = user.BadgeImageURL
	}

	// Add social links
	if user.GitHubUsername != "" {
		link := fmt.Sprintf("https://github.com/%s", user.GitHubUsername)
		prof.SocialLinks = append(prof.SocialLinks, link)
		c.logger.InfoContext(ctx, "discovered social link from tryhackme",
			"platform", "github", "link", link, "source", "tryhackme")
	}
	if user.TwitterUsername != "" {
		link := fmt.Sprintf("https://twitter.com/%s", user.TwitterUsername)
		prof.SocialLinks = append(prof.SocialLinks, link)
		c.logger.InfoContext(ctx, "discovered social link from tryhackme",
			"platform", "twitter", "link", link, "source", "tryhackme")
	}
	if user.LinkedInUsername != "" {
		link := fmt.Sprintf("https://linkedin.com/in/%s", user.LinkedInUsername)
		prof.SocialLinks = append(prof.SocialLinks, link)
		c.logger.InfoContext(ctx, "discovered social link from tryhackme",
			"platform", "linkedin", "link", link, "source", "tryhackme")
	}
	if user.InstagramUsername != "" {
		link := fmt.Sprintf("https://instagram.com/%s", user.InstagramUsername)
		prof.SocialLinks = append(prof.SocialLinks, link)
		c.logger.InfoContext(ctx, "discovered social link from tryhackme",
			"platform", "instagram", "link", link, "source", "tryhackme")
	}
	if user.RedditUsername != "" {
		link := fmt.Sprintf("https://reddit.com/user/%s", user.RedditUsername)
		prof.SocialLinks = append(prof.SocialLinks, link)
		c.logger.InfoContext(ctx, "discovered social link from tryhackme",
			"platform", "reddit", "link", link, "source", "tryhackme")
	}
	if user.DiscordUsername != "" {
		prof.Fields["discord"] = user.DiscordUsername
	}
	if user.PersonalWebsite != "" {
		prof.Website = user.PersonalWebsite
		prof.SocialLinks = append(prof.SocialLinks, user.PersonalWebsite)
		c.logger.InfoContext(ctx, "discovered social link from tryhackme",
			"platform", "website", "link", user.PersonalWebsite, "source", "tryhackme")
	}

	return prof, nil
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
