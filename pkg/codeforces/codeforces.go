// Package codeforces fetches Codeforces user profile data.
package codeforces

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

const platform = "codeforces"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)codeforces\.com/profile/([a-zA-Z0-9_.-]+)`)

// Match returns true if the URL is a Codeforces profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "codeforces.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Codeforces profiles are public.
func AuthRequired() bool { return false }

// Client handles Codeforces requests.
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

// New creates a Codeforces client.
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
	Status string    `json:"status"`
	Result []apiUser `json:"result"`
}

type apiUser struct {
	Handle           string `json:"handle"`
	FirstName        string `json:"firstName"`
	LastName         string `json:"lastName"`
	Country          string `json:"country"`
	City             string `json:"city"`
	Organization     string `json:"organization"`
	Rank             string `json:"rank"`
	MaxRank          string `json:"maxRank"`
	Avatar           string `json:"avatar"`
	TitlePhoto       string `json:"titlePhoto"`
	RegistrationTime int64  `json:"registrationTimeSeconds"`
	Rating           int    `json:"rating"`
	MaxRating        int    `json:"maxRating"`
	Contribution     int    `json:"contribution"`
	FriendOfCount    int    `json:"friendOfCount"`
}

// Fetch retrieves a Codeforces profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching codeforces profile", "url", urlStr, "username", username)

	apiURL := "https://codeforces.com/api/user.info?handles=" + username

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
		return nil, fmt.Errorf("failed to parse codeforces response: %w", err)
	}

	if resp.Status != "OK" || len(resp.Result) == 0 {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(&resp.Result[0], urlStr), nil
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

	// Location from country and city
	var locParts []string
	if data.City != "" {
		locParts = append(locParts, data.City)
	}
	if data.Country != "" {
		locParts = append(locParts, data.Country)
	}
	if len(locParts) > 0 {
		p.Location = strings.Join(locParts, ", ")
	}

	// Avatar - use titlePhoto if available, otherwise avatar
	if data.TitlePhoto != "" && !strings.Contains(data.TitlePhoto, "no-title") {
		p.AvatarURL = data.TitlePhoto
	} else if data.Avatar != "" && !strings.Contains(data.Avatar, "no-avatar") {
		p.AvatarURL = data.Avatar
	}

	// Organization as group
	if data.Organization != "" {
		p.Groups = append(p.Groups, data.Organization)
		p.Fields["organization"] = data.Organization
	}

	// Rating and rank
	if data.Rating > 0 {
		p.Fields["rating"] = strconv.Itoa(data.Rating)
	}
	if data.MaxRating > 0 {
		p.Fields["max_rating"] = strconv.Itoa(data.MaxRating)
	}
	if data.Rank != "" {
		p.Fields["rank"] = data.Rank
	}
	if data.MaxRank != "" {
		p.Fields["max_rank"] = data.MaxRank
	}

	if data.Contribution != 0 {
		p.Fields["contribution"] = strconv.Itoa(data.Contribution)
	}

	if data.FriendOfCount > 0 {
		p.Fields["friends"] = strconv.Itoa(data.FriendOfCount)
	}

	// Registration time
	if data.RegistrationTime > 0 {
		t := time.Unix(data.RegistrationTime, 0)
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
