// Package duolingo fetches Duolingo user profile data.
package duolingo

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "duolingo"

// platformInfo implements profile.Platform for Duolingo.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)duolingo\.com/profile/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Duolingo profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "duolingo.com/profile/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Duolingo profiles are public.
func AuthRequired() bool { return false }

// Client handles Duolingo requests.
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

// New creates a Duolingo client.
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

// userResponse represents the Duolingo API user response.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type userResponse struct {
	Users []struct {
		Username            string `json:"username"`
		Name                string `json:"name"`
		Picture             string `json:"picture"`
		Bio                 string `json:"bio"`
		TotalXP             int    `json:"totalXp"`
		Streak              int    `json:"streak"`
		CreatedAt           int64  `json:"creationDate"`
		CurrentCourseID     string `json:"currentCourseId"`
		LearningLanguage    string `json:"learningLanguage"`
		FromLanguage        string `json:"fromLanguage"`
		StreakExtendedToday bool   `json:"streakExtendedToday"`
		Courses             []struct {
			ID        string `json:"id"`
			Title     string `json:"title"`
			XP        int    `json:"xp"`
			Crowns    int    `json:"crowns"`
			FromLang  string `json:"fromLanguage"`
			LearnLang string `json:"learningLanguage"`
		} `json:"courses"`
	} `json:"users"`
}

// Fetch retrieves a Duolingo profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)

	c.logger.InfoContext(ctx, "fetching duolingo profile", "url", urlStr, "username", username)

	// Use the unofficial API endpoint
	apiURL := "https://www.duolingo.com/2017-06-30/users?username=" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpcache.UserAgent)
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseJSON(body, urlStr, username)
}

func parseJSON(data []byte, urlStr, username string) (*profile.Profile, error) {
	var resp userResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		// If parsing fails, return minimal profile
		return &profile.Profile{
			Platform:      platform,
			URL:           urlStr,
			Authenticated: false,
			Username:      username,
			DisplayName:   username,
			Fields:        make(map[string]string),
		}, err
	}
	if len(resp.Users) == 0 {
		// No users found, return minimal profile
		return &profile.Profile{
			Platform:      platform,
			URL:           urlStr,
			Authenticated: false,
			Username:      username,
			DisplayName:   username,
			Fields:        make(map[string]string),
		}, nil
	}

	user := resp.Users[0]

	prof := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      user.Username,
		DisplayName:   user.Username,
		Fields:        make(map[string]string),
	}

	// Set display name if available
	if user.Name != "" {
		prof.DisplayName = user.Name
	}

	// Set avatar
	if user.Picture != "" {
		prof.AvatarURL = user.Picture
	}

	// Set bio
	if user.Bio != "" {
		prof.Bio = user.Bio
	}

	// Set created at from timestamp
	if user.CreatedAt > 0 {
		t := time.Unix(user.CreatedAt/1000, 0) // Convert milliseconds to seconds
		prof.CreatedAt = t.Format("2006-01-02")
	}

	// Set streak
	if user.Streak > 0 {
		prof.Fields["streak"] = strconv.Itoa(user.Streak)
	}

	// Set total XP
	if user.TotalXP > 0 {
		prof.Fields["total_xp"] = strconv.Itoa(user.TotalXP)
	}

	// Set current learning language
	if user.LearningLanguage != "" {
		prof.Fields["learning_language"] = user.LearningLanguage
	}

	// Set native/from language
	if user.FromLanguage != "" {
		prof.Fields["from_language"] = user.FromLanguage
	}

	// Set courses as groups
	for _, course := range user.Courses {
		if course.Title != "" {
			prof.Groups = append(prof.Groups, course.Title)
		}
	}

	return prof, nil
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
