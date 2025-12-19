// Package ionicforum fetches Ionic Forum user profile data.
package ionicforum

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "ionicforum"

// platformInfo implements profile.Platform for Ionic Forum.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)forum\.ionicframework\.com/u/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is an Ionic Forum user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "forum.ionicframework.com/u/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Ionic Forum profiles are public.
func AuthRequired() bool { return false }

// Client handles Ionic Forum requests.
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

// New creates an Ionic Forum client.
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

// discourseUser represents the Discourse API user response.
type discourseUser struct {
	User struct {
		ID               int    `json:"id"`
		Username         string `json:"username"`
		Name             string `json:"name"`
		AvatarTemplate   string `json:"avatar_template"`
		Title            string `json:"title"`
		TrustLevel       int    `json:"trust_level"`
		Admin            bool   `json:"admin"`
		Moderator        bool   `json:"moderator"`
		Bio              string `json:"bio_raw"`
		Website          string `json:"website"`
		Location         string `json:"location"`
		ProfileViewCount int    `json:"profile_view_count"`
		CreatedAt        string `json:"created_at"`
		LastSeenAt       string `json:"last_seen_at"`
		BadgeCount       int    `json:"badge_count"`
	} `json:"user"`
	UserBadges []struct {
		ID        int    `json:"id"`
		GrantedAt string `json:"granted_at"`
		Badge     badge  `json:"badge"`
		Count     int    `json:"count"`
		BadgeID   int    `json:"badge_id"`
	} `json:"user_badges"`
}

type badge struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	BadgeType   int    `json:"badge_type"` // 1=gold, 2=silver, 3=bronze
}

// Fetch retrieves an Ionic Forum profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching ionic forum profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://forum.ionicframework.com/u/%s.json", username)

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

	var data discourseUser
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to parse ionic forum response: %w", err)
	}

	if data.User.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(&data, urlStr), nil
}

func parseProfile(data *discourseUser, urlStr string) *profile.Profile {
	p := &profile.Profile{
		URL:         urlStr,
		Platform:    platform,
		Username:    data.User.Username,
		DisplayName: data.User.Name,
		Bio:         data.User.Bio,
		Location:    data.User.Location,
		Fields:      make(map[string]string),
	}

	// Parse website - Ionic forum returns twitter.com URLs
	if data.User.Website != "" {
		website := data.User.Website
		// Add https:// if missing
		if !strings.HasPrefix(website, "http") {
			website = "https://" + website
		}
		p.Website = website
		// Also add as social link if it's Twitter
		if strings.Contains(website, "twitter.com") || strings.Contains(website, "x.com") {
			p.SocialLinks = append(p.SocialLinks, website)
		}
	}

	// Build avatar URL (use size 240 for good quality)
	if data.User.AvatarTemplate != "" {
		avatar := strings.Replace(data.User.AvatarTemplate, "{size}", "240", 1)
		if !strings.HasPrefix(avatar, "http") {
			avatar = "https://forum.ionicframework.com" + avatar
		}
		p.AvatarURL = avatar
	}

	// Add title if present
	if data.User.Title != "" {
		p.Fields["title"] = data.User.Title
	}

	// Add trust level
	p.Fields["trust_level"] = fmt.Sprintf("%d", data.User.TrustLevel)

	// Add admin/moderator status
	if data.User.Admin {
		p.Fields["admin"] = "true"
	}
	if data.User.Moderator {
		p.Fields["moderator"] = "true"
	}

	// Add profile view count
	if data.User.ProfileViewCount > 0 {
		p.Fields["profile_views"] = fmt.Sprintf("%d", data.User.ProfileViewCount)
	}

	// Add badge count
	if data.User.BadgeCount > 0 {
		p.Fields["badge_count"] = fmt.Sprintf("%d", data.User.BadgeCount)
	}

	// Add created date
	if data.User.CreatedAt != "" {
		p.Fields["created_at"] = data.User.CreatedAt
	}

	// Parse badges
	if len(data.UserBadges) > 0 {
		var badgeNames []string
		for _, ub := range data.UserBadges {
			badgeName := ub.Badge.Name
			if ub.Count > 1 {
				badgeName = fmt.Sprintf("%s (×%d)", badgeName, ub.Count)
			}
			badgeNames = append(badgeNames, badgeName)
		}
		if len(badgeNames) > 0 {
			p.Fields["badges"] = strings.Join(badgeNames, ", ")
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
