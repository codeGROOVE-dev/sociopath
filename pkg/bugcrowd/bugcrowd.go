// Package bugcrowd fetches Bugcrowd researcher profile data via the profile-service API.
package bugcrowd

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

const platform = "bugcrowd"

// platformInfo implements profile.Platform for Bugcrowd.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSecurity }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)bugcrowd\.com/(?:h/)?([a-zA-Z0-9_-]+)`)

// Country code to country name mapping.
var countryNames = map[string]string{
	"CAN": "Canada", "USA": "United States", "GBR": "United Kingdom", "AUS": "Australia",
	"DEU": "Germany", "FRA": "France", "NLD": "Netherlands", "IND": "India", "BRA": "Brazil",
	"JPN": "Japan", "CHN": "China", "KOR": "South Korea", "SGP": "Singapore", "NZL": "New Zealand",
	"IRL": "Ireland", "CHE": "Switzerland", "SWE": "Sweden", "NOR": "Norway", "DNK": "Denmark",
	"FIN": "Finland", "ESP": "Spain", "ITA": "Italy", "PRT": "Portugal", "POL": "Poland",
	"AUT": "Austria", "BEL": "Belgium", "CZE": "Czech Republic", "HUN": "Hungary", "ROU": "Romania",
	"UKR": "Ukraine", "RUS": "Russia", "TUR": "Turkey", "ISR": "Israel", "ARE": "UAE",
	"SAU": "Saudi Arabia", "EGY": "Egypt", "ZAF": "South Africa", "NGA": "Nigeria", "KEN": "Kenya",
	"MEX": "Mexico", "ARG": "Argentina", "CHL": "Chile", "COL": "Colombia", "PER": "Peru",
	"VNM": "Vietnam", "THA": "Thailand", "IDN": "Indonesia", "MYS": "Malaysia", "PHL": "Philippines",
	"PAK": "Pakistan", "BGD": "Bangladesh", "LKA": "Sri Lanka", "NPL": "Nepal",
}

// Match returns true if the URL is a Bugcrowd profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "bugcrowd.com/") {
		return false
	}
	// Skip non-profile pages
	skipPaths := []string{"/programs/", "/engagements/", "/settings/", "/submissions/", "/leaderboard", "/api/"}
	for _, sp := range skipPaths {
		if strings.Contains(lower, sp) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Bugcrowd profiles are public.
func AuthRequired() bool { return false }

// Client handles Bugcrowd requests.
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

// New creates a Bugcrowd client.
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

// API response structure.
//
//nolint:govet // field alignment not critical for JSON parsing
type profileResponse struct {
	Username          string  `json:"username"`
	AvatarURL         string  `json:"avatarUrl"`
	BannerImageURL    string  `json:"bannerImageUrl"`
	AccentColor       *string `json:"accentColor"`
	CountryCode       string  `json:"countryCode"`
	TwitterUsername   *string `json:"twitterUsername"`
	LinkedinURL       string  `json:"linkedinUrl"`
	Website           string  `json:"website"`
	Biography         string  `json:"biography"`
	IdentityVerified  bool    `json:"identityVerified"`
	ProfileVisibility string  `json:"profileVisibility"`
}

// performanceStatsResponse contains statistics including activity date range.
type performanceStatsResponse struct {
	DateRanges []dateRange `json:"dateRanges"`
}

type dateRange struct {
	Name      string `json:"name"`
	StartDate string `json:"startDate"`
	EndDate   string `json:"endDate"`
	Active    bool   `json:"active"`
}

// Fetch retrieves a Bugcrowd profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching bugcrowd profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://bugcrowd.com/profile-service/v1/profiles/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp profileResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse bugcrowd response: %w", err)
	}

	// Check for empty response (user not found)
	if resp.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	// Fetch performance statistics for account creation date
	createdAt := c.fetchCreatedAt(ctx, username)

	return parseProfile(ctx, &resp, urlStr, createdAt, c.logger), nil
}

// fetchCreatedAt retrieves the account creation date from performance statistics.
func (c *Client) fetchCreatedAt(ctx context.Context, username string) string {
	statsURL := fmt.Sprintf("https://bugcrowd.com/profile-service/v1/profiles/%s/performanceStatistics", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statsURL, http.NoBody)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return ""
	}

	var stats performanceStatsResponse
	if err := json.Unmarshal(body, &stats); err != nil {
		return ""
	}

	// Find the "All time" date range - its start date is the account creation/first activity date
	for _, dr := range stats.DateRanges {
		if dr.Name == "All time" && dr.StartDate != "" {
			return dr.StartDate
		}
	}

	return ""
}

func parseProfile(ctx context.Context, data *profileResponse, profileURL, createdAt string, logger *slog.Logger) *profile.Profile {
	prof := &profile.Profile{
		Platform:  platform,
		URL:       profileURL,
		Username:  data.Username,
		Bio:       data.Biography,
		CreatedAt: createdAt,
		Fields:    make(map[string]string),
	}

	// Prefer banner image (typically a real photo) over generic avatar icon
	if data.BannerImageURL != "" {
		prof.AvatarURL = data.BannerImageURL
	} else if data.AvatarURL != "" {
		prof.AvatarURL = data.AvatarURL
	}

	// Convert country code to country name
	if data.CountryCode != "" {
		if countryName, ok := countryNames[data.CountryCode]; ok {
			prof.Location = countryName
		} else {
			prof.Location = data.CountryCode
		}
		prof.Fields["country_code"] = data.CountryCode
	}

	// Website - check if it's actually a GitHub link
	if data.Website != "" {
		prof.Website = data.Website
		prof.Fields["website"] = data.Website

		// If website is a GitHub URL, also add it as a social link
		if strings.Contains(strings.ToLower(data.Website), "github.com/") {
			logger.InfoContext(ctx, "discovered username from bugcrowd",
				"platform", "github", "url", data.Website, "source", "bugcrowd")
			prof.SocialLinks = append(prof.SocialLinks, data.Website)
			prof.Fields["github"] = data.Website
		}
	}

	// LinkedIn
	if data.LinkedinURL != "" {
		logger.InfoContext(ctx, "discovered username from bugcrowd",
			"platform", "linkedin", "url", data.LinkedinURL, "source", "bugcrowd")
		prof.SocialLinks = append(prof.SocialLinks, data.LinkedinURL)
		prof.Fields["linkedin"] = data.LinkedinURL
	}

	// Twitter
	if data.TwitterUsername != nil && *data.TwitterUsername != "" {
		twitterURL := "https://twitter.com/" + *data.TwitterUsername
		logger.InfoContext(ctx, "discovered username from bugcrowd",
			"platform", "twitter", "username", *data.TwitterUsername, "source", "bugcrowd")
		prof.SocialLinks = append(prof.SocialLinks, twitterURL)
		prof.Fields["twitter"] = twitterURL
	}

	// Verified status
	if data.IdentityVerified {
		prof.Badges = map[string]string{"Verified": "1"}
	}

	// Default name to username if not provided
	if prof.DisplayName == "" {
		prof.DisplayName = prof.Username
	}

	return prof
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
