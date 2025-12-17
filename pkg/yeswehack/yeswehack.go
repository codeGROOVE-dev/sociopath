// Package yeswehack fetches YesWeHack bug bounty researcher profile data.
package yeswehack

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

const platform = "yeswehack"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSecurity }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)yeswehack\.com/hunters/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a YesWeHack profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "yeswehack.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because YesWeHack profiles are public.
func AuthRequired() bool { return false }

// Client handles YesWeHack requests.
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

// New creates a YesWeHack client.
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

type apiUser struct {
	Username   string `json:"username"`
	Avatar     string `json:"avatar"`
	PublicInfo struct {
		Country string `json:"country"`
		Bio     string `json:"bio"`
		Website string `json:"website"`
		Twitter string `json:"twitter"`
		GitHub  string `json:"github"`
	} `json:"public_infos"`
	Stats struct {
		Rank          int     `json:"rank"`
		NbReport      int     `json:"nb_report"`
		NbBounty      int     `json:"nb_bounty"`
		TotalBounty   int     `json:"total_bounty"`
		AveragePoints float64 `json:"average_points"`
	} `json:"stats"`
}

// Fetch retrieves a YesWeHack profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching yeswehack profile", "url", urlStr, "username", username)

	apiURL := "https://api.yeswehack.com/hunters/" + username

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
		return nil, fmt.Errorf("failed to parse yeswehack response: %w", err)
	}

	if user.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(&user, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    data.Username,
		DisplayName: data.Username,
		Fields:      make(map[string]string),
	}

	if data.Avatar != "" {
		p.AvatarURL = data.Avatar
	}

	if data.PublicInfo.Country != "" {
		p.Location = data.PublicInfo.Country
	}

	if data.PublicInfo.Bio != "" {
		p.Bio = data.PublicInfo.Bio
	}

	if data.PublicInfo.Website != "" {
		p.Website = data.PublicInfo.Website
	}

	// Stats
	if data.Stats.Rank > 0 {
		p.Fields["rank"] = strconv.Itoa(data.Stats.Rank)
	}

	if data.Stats.NbReport > 0 {
		p.Fields["reports"] = strconv.Itoa(data.Stats.NbReport)
	}

	if data.Stats.NbBounty > 0 {
		p.Fields["bounties"] = strconv.Itoa(data.Stats.NbBounty)
	}

	// Social links
	if data.PublicInfo.Twitter != "" {
		tw := data.PublicInfo.Twitter
		if !strings.HasPrefix(tw, "http") {
			tw = "https://twitter.com/" + tw
		}
		p.SocialLinks = append(p.SocialLinks, tw)
	}

	if data.PublicInfo.GitHub != "" {
		gh := data.PublicInfo.GitHub
		if !strings.HasPrefix(gh, "http") {
			gh = "https://github.com/" + gh
		}
		p.SocialLinks = append(p.SocialLinks, gh)
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
