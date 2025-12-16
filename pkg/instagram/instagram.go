// Package instagram provides Instagram profile fetching via anonymous API.
package instagram

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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

const platform = "instagram"

// platformInfo implements profile.Platform for Instagram.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return false }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is an Instagram profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "instagram.com/") {
		return false
	}
	// Extract username and validate it's a profile URL
	username := extractUsername(urlStr)
	return username != ""
}

var usernamePattern = regexp.MustCompile(`(?i)instagram\.com/([a-zA-Z0-9_.]+)`)

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) < 2 {
		return ""
	}
	username := matches[1]

	// Skip non-profile paths
	systemPaths := map[string]bool{
		"p": true, "reel": true, "reels": true, "stories": true,
		"explore": true, "direct": true, "accounts": true,
		"about": true, "legal": true, "privacy": true,
		"terms": true, "api": true, "developer": true,
	}
	if systemPaths[strings.ToLower(username)] {
		return ""
	}

	return username
}

// Client handles Instagram requests.
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

// New creates an Instagram client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves an Instagram profile using the anonymous API.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching instagram profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://i.instagram.com/api/v1/users/web_profile_info/?username=%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Required header for anonymous access
	req.Header.Set("X-Ig-App-Id", "936619743392459")
	req.Header.Set("User-Agent", httpcache.UserAgent)

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, fmt.Errorf("fetch instagram API: %w", err)
	}

	return c.parseResponse(body, urlStr)
}

func (c *Client) parseResponse(data []byte, urlStr string) (*profile.Profile, error) {
	var resp apiResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	user := resp.Data.User
	if user.Username == "" {
		return nil, errors.New("user not found or private")
	}

	p := &profile.Profile{
		Platform:    platform,
		URL:         urlStr,
		Username:    user.Username,
		DisplayName: user.FullName,
		Bio:         user.Biography,
		AvatarURL:   user.ProfilePicURLHD,
		DatabaseID:  user.ID,
		Fields:      make(map[string]string),
	}

	// Use standard avatar if HD not available
	if p.AvatarURL == "" {
		p.AvatarURL = user.ProfilePicURL
	}

	// Extract website from external URL
	if user.ExternalURL != "" {
		p.Website = user.ExternalURL
	}

	// Collect additional links
	for _, link := range user.BioLinks {
		if link.URL != "" && link.URL != user.ExternalURL {
			p.SocialLinks = append(p.SocialLinks, link.URL)
		}
	}

	// Store counts in fields
	if user.EdgeFollowedBy.Count > 0 {
		p.Fields["followers"] = strconv.Itoa(user.EdgeFollowedBy.Count)
	}
	if user.EdgeFollow.Count > 0 {
		p.Fields["following"] = strconv.Itoa(user.EdgeFollow.Count)
	}
	if user.EdgeOwnerToTimelineMedia.Count > 0 {
		p.Fields["posts"] = strconv.Itoa(user.EdgeOwnerToTimelineMedia.Count)
	}

	// Store verified and account type in fields
	if user.IsVerified {
		p.Fields["verified"] = "true"
	}
	if user.IsBusinessAccount || user.IsProfessionalAccount {
		p.Fields["account_type"] = "professional"
	}
	if user.IsPrivate {
		p.Fields["private"] = "true"
	}

	// Store pronouns if available
	if len(user.Pronouns) > 0 {
		p.Fields["pronouns"] = strings.Join(user.Pronouns, ", ")
	}

	// Store category if available
	if user.CategoryName != "" {
		p.Fields["category"] = user.CategoryName
	} else if user.BusinessCategoryName != "" && user.BusinessCategoryName != "None" {
		p.Fields["category"] = user.BusinessCategoryName
	}

	// Note if user is on Threads
	if user.ShowTextPostAppBadge {
		p.Fields["threads"] = "true"
	}

	c.logger.Debug("parsed instagram profile",
		"username", p.Username,
		"name", p.DisplayName,
		"verified", user.IsVerified,
		"followers", user.EdgeFollowedBy.Count,
	)

	return p, nil
}

// apiResponse represents the Instagram API response structure.
type apiResponse struct {
	Data struct {
		User userInfo `json:"user"`
	} `json:"data"`
}

type userInfo struct {
	ID                       string    `json:"id"`
	Username                 string    `json:"username"`
	FullName                 string    `json:"full_name"`
	Biography                string    `json:"biography"`
	ProfilePicURL            string    `json:"profile_pic_url"`
	ProfilePicURLHD          string    `json:"profile_pic_url_hd"`
	ExternalURL              string    `json:"external_url"`
	CategoryName             string    `json:"category_name"`
	BusinessCategoryName     string    `json:"business_category_name"`
	BioLinks                 []bioLink `json:"bio_links"`
	Pronouns                 []string  `json:"pronouns"`
	EdgeFollowedBy           count     `json:"edge_followed_by"`
	EdgeFollow               count     `json:"edge_follow"`
	EdgeOwnerToTimelineMedia count     `json:"edge_owner_to_timeline_media"`
	ShowTextPostAppBadge     bool      `json:"show_text_post_app_badge"`
	IsVerified               bool      `json:"is_verified"`
	IsBusinessAccount        bool      `json:"is_business_account"`
	IsProfessionalAccount    bool      `json:"is_professional_account"`
	IsPrivate                bool      `json:"is_private"`
}

type count struct {
	Count int `json:"count"`
}

type bioLink struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}
