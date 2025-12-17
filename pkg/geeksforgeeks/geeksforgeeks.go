// Package geeksforgeeks fetches GeeksforGeeks user profile data.
package geeksforgeeks

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

const platform = "geeksforgeeks"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)(?:geeksforgeeks\.org|gfg\.dev)/user/([a-zA-Z0-9_]+)`)

// Match returns true if the URL is a GeeksforGeeks profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "geeksforgeeks.org") && !strings.Contains(lower, "gfg.dev") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because GeeksforGeeks profiles are public.
func AuthRequired() bool { return false }

// Client handles GeeksforGeeks requests.
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

// New creates a GeeksforGeeks client.
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

//nolint:govet // fieldalignment: struct ordering for JSON readability
type apiResponse struct {
	UserName            string `json:"userName"`
	ProfilePicture      string `json:"profilePicture"`
	Institute           string `json:"institute"`
	InstituteRank       string `json:"instituteRank"`
	CurrentStreak       string `json:"currentStreak"`
	MaxStreak           string `json:"maxStreak"`
	CodingScore         int    `json:"codingScore"`
	TotalProblemsSolved int    `json:"totalProblemsSolved"`
	MonthlyCodingScore  int    `json:"monthlyCodingScore"`
	Languages           string `json:"languages"`
}

// Fetch retrieves a GeeksforGeeks profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching geeksforgeeks profile", "url", urlStr, "username", username)

	apiURL := "https://authapi.geeksforgeeks.org/api-get/user-profile-info/?handle=" + username

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
		return nil, fmt.Errorf("failed to parse geeksforgeeks response: %w", err)
	}

	if resp.UserName == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(&resp, urlStr), nil
}

func parseProfile(data *apiResponse, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    data.UserName,
		DisplayName: data.UserName,
		Fields:      make(map[string]string),
	}

	if data.ProfilePicture != "" {
		p.AvatarURL = data.ProfilePicture
	}

	if data.Institute != "" {
		p.Groups = append(p.Groups, data.Institute)
		p.Fields["institute"] = data.Institute
	}

	if data.InstituteRank != "" {
		p.Fields["institute_rank"] = data.InstituteRank
	}

	if data.CurrentStreak != "" && data.CurrentStreak != "0" {
		p.Fields["current_streak"] = data.CurrentStreak
	}

	if data.MaxStreak != "" && data.MaxStreak != "0" {
		p.Fields["max_streak"] = data.MaxStreak
	}

	if data.CodingScore > 0 {
		p.Fields["coding_score"] = strconv.Itoa(data.CodingScore)
	}

	if data.TotalProblemsSolved > 0 {
		p.Fields["problems_solved"] = strconv.Itoa(data.TotalProblemsSolved)
	}

	if data.Languages != "" {
		p.Fields["languages"] = data.Languages
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
