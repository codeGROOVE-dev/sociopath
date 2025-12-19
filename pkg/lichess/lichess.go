// Package lichess fetches Lichess.org chess profile data.
package lichess

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

const platform = "lichess"

// platformInfo implements profile.Platform for Lichess.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeGaming }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)lichess\.org/@/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Lichess profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "lichess.org/@/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Lichess profiles are public.
func AuthRequired() bool { return false }

// Client handles Lichess requests.
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

// New creates a Lichess client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
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

// Fetch retrieves a Lichess profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	// Lichess has a public JSON API
	apiURL := fmt.Sprintf("https://lichess.org/api/user/%s", username)
	c.logger.InfoContext(ctx, "fetching lichess profile", "url", apiURL, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, username)
}

// lichessUser represents the Lichess API user response.
type lichessUser struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Title        string `json:"title"`        // GM, IM, etc.
	Patron       bool   `json:"patron"`       // Patron status
	CreatedAt    int64  `json:"createdAt"`    // Unix timestamp in milliseconds
	SeenAt       int64  `json:"seenAt"`       // Last seen timestamp
	PlayTime     struct {
		Total int64 `json:"total"` // Total play time in seconds
		TV    int64 `json:"tv"`    // Time on Lichess TV
	} `json:"playTime"`
	URL     string `json:"url"`
	Count   struct {
		All      int `json:"all"`
		Rated    int `json:"rated"`
		AI       int `json:"ai"`
		Draw     int `json:"draw"`
		DrawH    int `json:"drawH"`
		Loss     int `json:"loss"`
		LossH    int `json:"lossH"`
		Win      int `json:"win"`
		WinH     int `json:"winH"`
		Bookmark int `json:"bookmark"`
		Playing  int `json:"playing"`
		Import   int `json:"import"`
		Me       int `json:"me"`
	} `json:"count"`
	Followable bool              `json:"followable"`
	Following  bool              `json:"following"`
	Blocking   bool              `json:"blocking"`
	FollowsYou bool              `json:"followsYou"`
	Perfs      map[string]struct {
		Games int `json:"games"`
		Rating int `json:"rating"`
		RD     int `json:"rd"`
		Prog   int `json:"prog"`
		Prov   bool `json:"prov,omitempty"`
	} `json:"perfs"`
	Profile struct {
		Country   string `json:"country,omitempty"`
		Location  string `json:"location,omitempty"`
		Bio       string `json:"bio,omitempty"`
		FirstName string `json:"firstName,omitempty"`
		LastName  string `json:"lastName,omitempty"`
		Links     string `json:"links,omitempty"`
	} `json:"profile,omitempty"`
}

func parseProfile(jsonData []byte, username string) (*profile.Profile, error) {
	var user lichessUser
	if err := json.Unmarshal(jsonData, &user); err != nil {
		// Check if 404
		if strings.Contains(string(jsonData), "404") {
			return nil, profile.ErrProfileNotFound
		}
		return nil, fmt.Errorf("failed to parse lichess JSON: %w", err)
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      fmt.Sprintf("https://lichess.org/@/%s", username),
		Username: user.Username,
		DisplayName: user.Username,
		Bio:      user.Profile.Bio,
		Location: user.Profile.Location,
		Fields:   make(map[string]string),
	}

	// Add title if present (GM, IM, etc.)
	if user.Title != "" {
		p.Fields["title"] = user.Title
		p.DisplayName = user.Title + " " + user.Username
	}

	// Add country
	if user.Profile.Country != "" {
		p.Fields["country"] = user.Profile.Country
	}

	// Add name if available
	if user.Profile.FirstName != "" || user.Profile.LastName != "" {
		fullName := strings.TrimSpace(user.Profile.FirstName + " " + user.Profile.LastName)
		if fullName != "" {
			p.Fields["name"] = fullName
		}
	}

	// Add patron status
	if user.Patron {
		p.Fields["patron"] = "true"
	}

	// Add member since
	if user.CreatedAt > 0 {
		createdTime := time.UnixMilli(user.CreatedAt)
		p.Fields["member_since"] = createdTime.Format("January 2, 2006")
	}

	// Add play time
	if user.PlayTime.Total > 0 {
		days := user.PlayTime.Total / 86400
		hours := (user.PlayTime.Total % 86400) / 3600
		p.Fields["time_played"] = fmt.Sprintf("%d days, %d hours", days, hours)
	}

	// Add TV time
	if user.PlayTime.TV > 0 {
		days := user.PlayTime.TV / 86400
		hours := (user.PlayTime.TV % 86400) / 3600
		p.Fields["tv_time"] = fmt.Sprintf("%d days, %d hours", days, hours)
	}

	// Add total games
	if user.Count.All > 0 {
		p.Fields["total_games"] = strconv.Itoa(user.Count.All)
	}

	// Add ratings for each game type
	for perfType, perf := range user.Perfs {
		if perf.Games > 0 {
			p.Fields[perfType+"_rating"] = strconv.Itoa(perf.Rating)
			p.Fields[perfType+"_games"] = strconv.Itoa(perf.Games)
		}
	}

	// Extract social links from profile.Links
	if user.Profile.Links != "" {
		links := strings.Split(user.Profile.Links, "\n")
		for _, link := range links {
			link = strings.TrimSpace(link)
			if link != "" && strings.HasPrefix(link, "http") {
				p.SocialLinks = append(p.SocialLinks, link)
			}
		}
	}

	return p, nil
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
