// Package intigriti fetches Intigriti bug bounty researcher profile data.
package intigriti

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

const platform = "intigriti"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSecurity }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)(?:intigriti\.com|app\.intigriti\.com)/(?:profile/|researcher/)?([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is an Intigriti profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "intigriti.com") {
		return false
	}
	// Exclude non-profile paths
	excluded := []string{"/programs/", "/company/", "/bounty/", "/report/"}
	for _, ex := range excluded {
		if strings.Contains(lower, ex) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Intigriti profiles are public.
func AuthRequired() bool { return false }

// Client handles Intigriti requests.
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

// New creates an Intigriti client.
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
type apiUser struct {
	UserName        string `json:"userName"`
	AvatarURL       string `json:"avatarUrl"`
	Reputation      int    `json:"reputation"`
	Rank            int    `json:"rank"`
	Streak          int    `json:"streak"`
	AcceptedReports int    `json:"acceptedReports"`
	Country         string `json:"country"`
	Bio             string `json:"bio"`
}

// Fetch retrieves an Intigriti profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching intigriti profile", "url", urlStr, "username", username)

	apiURL := "https://app.intigriti.com/api/user/public/profile/" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var user apiUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse intigriti response: %w", err)
	}

	if user.UserName == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(&user, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    data.UserName,
		DisplayName: data.UserName,
		Fields:      make(map[string]string),
	}

	if data.AvatarURL != "" {
		p.AvatarURL = data.AvatarURL
	}

	if data.Country != "" {
		p.Location = data.Country
	}

	if data.Bio != "" {
		p.Bio = data.Bio
	}

	if data.Reputation > 0 {
		p.Fields["reputation"] = strconv.Itoa(data.Reputation)
	}

	if data.Rank > 0 {
		p.Fields["rank"] = strconv.Itoa(data.Rank)
	}

	if data.Streak > 0 {
		p.Fields["streak"] = strconv.Itoa(data.Streak)
	}

	if data.AcceptedReports > 0 {
		p.Fields["accepted_reports"] = strconv.Itoa(data.AcceptedReports)
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
