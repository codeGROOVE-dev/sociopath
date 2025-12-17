// Package monkeytype fetches Monkeytype user profile data.
package monkeytype

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

const platform = "monkeytype"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)monkeytype\.com/profile/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Monkeytype profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "monkeytype.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Monkeytype profiles are public.
func AuthRequired() bool { return false }

// Client handles Monkeytype requests.
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

// New creates a Monkeytype client.
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
	Message string  `json:"message"`
	Data    apiUser `json:"data"`
}

//nolint:govet // fieldalignment: struct contains embedded structs with complex alignment
type apiUser struct {
	TypingStats    apiTypingStats    `json:"typingStats"`
	PersonalBests  apiPersonalBests  `json:"personalBests"`
	ProfileDetails apiProfileDetails `json:"profileDetails"`
	Name           string            `json:"name"`
	AddedAt        int64             `json:"addedAt"`
	TimeTyping     float64           `json:"timeTyping"`
	Streak         int               `json:"streak"`
	MaxStreak      int               `json:"maxStreak"`
	XP             int               `json:"xp"`
	CompletedTests int               `json:"completedTests"`
}

type apiTypingStats struct {
	CompletedTests int     `json:"completedTests"`
	StartedTests   int     `json:"startedTests"`
	TimeTyping     float64 `json:"timeTyping"`
}

type apiPersonalBests struct {
	Time  map[string][]apiBest `json:"time"`
	Words map[string][]apiBest `json:"words"`
}

type apiBest struct {
	Difficulty string  `json:"difficulty"`
	Language   string  `json:"language"`
	WPM        float64 `json:"wpm"`
	Acc        float64 `json:"acc"`
	Raw        float64 `json:"raw"`
	Timestamp  int64   `json:"timestamp"`
}

type apiProfileDetails struct {
	Bio            string `json:"bio"`
	Keyboard       string `json:"keyboard"`
	SocialProfiles struct {
		GitHub  string `json:"github"`
		Twitter string `json:"twitter"`
		Website string `json:"website"`
	} `json:"socialProfiles"`
}

// Fetch retrieves a Monkeytype profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching monkeytype profile", "url", urlStr, "username", username)

	apiURL := "https://api.monkeytype.com/users/" + username + "/profile"

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
		return nil, fmt.Errorf("failed to parse monkeytype response: %w", err)
	}

	if resp.Message != "Profile retrieved" || resp.Data.Name == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(&resp.Data, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    data.Name,
		DisplayName: data.Name,
		Fields:      make(map[string]string),
	}

	// Bio
	if data.ProfileDetails.Bio != "" {
		p.Bio = data.ProfileDetails.Bio
	}

	// Keyboard
	if data.ProfileDetails.Keyboard != "" {
		p.Fields["keyboard"] = data.ProfileDetails.Keyboard
	}

	// XP and stats
	if data.XP > 0 {
		p.Fields["xp"] = strconv.Itoa(data.XP)
	}
	if data.CompletedTests > 0 {
		p.Fields["completed_tests"] = strconv.Itoa(data.CompletedTests)
	}
	if data.Streak > 0 {
		p.Fields["streak"] = strconv.Itoa(data.Streak)
	}
	if data.MaxStreak > 0 {
		p.Fields["max_streak"] = strconv.Itoa(data.MaxStreak)
	}
	if data.TimeTyping > 0 {
		hours := data.TimeTyping / 3600
		p.Fields["time_typing"] = fmt.Sprintf("%.1f hours", hours)
	}

	// Best WPM for 60s test
	if bests, ok := data.PersonalBests.Time["60"]; ok && len(bests) > 0 {
		best := bests[0]
		p.Fields["best_wpm_60s"] = fmt.Sprintf("%.0f", best.WPM)
		p.Fields["best_accuracy_60s"] = fmt.Sprintf("%.1f%%", best.Acc)
	}

	// Social links
	if gh := data.ProfileDetails.SocialProfiles.GitHub; gh != "" {
		p.SocialLinks = append(p.SocialLinks, "https://github.com/"+gh)
	}
	if tw := data.ProfileDetails.SocialProfiles.Twitter; tw != "" {
		p.SocialLinks = append(p.SocialLinks, "https://twitter.com/"+tw)
	}
	if website := data.ProfileDetails.SocialProfiles.Website; website != "" {
		if !strings.HasPrefix(website, "http") {
			website = "https://" + website
		}
		p.Website = website
	}

	// Created at
	if data.AddedAt > 0 {
		t := time.UnixMilli(data.AddedAt)
		p.CreatedAt = t.Format(time.RFC3339)
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
