// Package topcoder fetches Topcoder user profile data.
package topcoder

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

const platform = "topcoder"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)topcoder\.com/members/([a-zA-Z0-9_.-]+)`)

// Match returns true if the URL is a Topcoder profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "topcoder.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Topcoder profiles are public.
func AuthRequired() bool { return false }

// Client handles Topcoder requests.
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

// New creates a Topcoder client.
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
	Handle          string `json:"handle"`
	FirstName       string `json:"firstName"`
	LastName        string `json:"lastName"`
	Country         string `json:"country"`
	HomeCountryCode string `json:"homeCountryCode"`
	Description     string `json:"description"`
	PhotoURL        string `json:"photoURL"`
	CreatedAt       int64  `json:"createdAt"`
	MaxRating       struct {
		Rating int    `json:"rating"`
		Track  string `json:"track"`
	} `json:"maxRating"`
	Stats *apiStats `json:"stats"`
}

type apiStats struct {
	Wins        int `json:"wins"`
	Challenges  int `json:"challenges"`
	Submissions int `json:"submissions"`
}

// Fetch retrieves a Topcoder profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching topcoder profile", "url", urlStr, "username", username)

	apiURL := "https://api.topcoder.com/v5/members/" + username

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
		return nil, fmt.Errorf("failed to parse topcoder response: %w", err)
	}

	if user.Handle == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(&user, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Handle,
		Fields:   make(map[string]string),
	}

	// Build display name from first/last name
	var nameParts []string
	if data.FirstName != "" {
		nameParts = append(nameParts, data.FirstName)
	}
	if data.LastName != "" {
		nameParts = append(nameParts, data.LastName)
	}
	if len(nameParts) > 0 {
		p.DisplayName = strings.Join(nameParts, " ")
	} else {
		p.DisplayName = data.Handle
	}

	// Location
	if data.Country != "" {
		p.Location = data.Country
	}

	// Bio/Description
	if data.Description != "" {
		p.Bio = data.Description
	}

	// Avatar
	if data.PhotoURL != "" {
		p.AvatarURL = data.PhotoURL
	}

	// Max rating
	if data.MaxRating.Rating > 0 {
		p.Fields["max_rating"] = strconv.Itoa(data.MaxRating.Rating)
		if data.MaxRating.Track != "" {
			p.Fields["top_track"] = data.MaxRating.Track
		}
	}

	// Stats
	if data.Stats != nil {
		if data.Stats.Wins > 0 {
			p.Fields["wins"] = strconv.Itoa(data.Stats.Wins)
		}
		if data.Stats.Challenges > 0 {
			p.Fields["challenges"] = strconv.Itoa(data.Stats.Challenges)
		}
	}

	// Created at
	if data.CreatedAt > 0 {
		t := time.UnixMilli(data.CreatedAt)
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
