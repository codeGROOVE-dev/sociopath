// Package boardgamegeek fetches BoardGameGeek user profile data.
package boardgamegeek

import (
	"context"
	"encoding/xml"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "boardgamegeek"

// platformInfo implements profile.Platform for BoardGameGeek.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)boardgamegeek\.com/(?:user|profile)/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a BoardGameGeek profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "boardgamegeek.com/") {
		return false
	}
	if !strings.Contains(lower, "/user/") && !strings.Contains(lower, "/profile/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because BoardGameGeek profiles are public.
func AuthRequired() bool { return false }

// Client handles BoardGameGeek requests.
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

// New creates a BoardGameGeek client.
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

// userResponse represents the BGG XML API user response.
type userResponse struct {
	XMLName        xml.Name `xml:"user"`
	ID             string   `xml:"id,attr"`
	Name           string   `xml:"name,attr"`
	FirstName      string   `xml:"firstname>value"`
	LastName       string   `xml:"lastname>value"`
	AvatarLink     string   `xml:"avatarlink>value"`
	YearRegistered string   `xml:"yearregistered>value"`
	LastLogin      string   `xml:"lastlogin>value"`
	StateOrProv    string   `xml:"stateorprovince>value"`
	Country        string   `xml:"country>value"`
	WebAddress     string   `xml:"webaddress>value"`
	TradeRating    string   `xml:"traderating>value"`
}

// Fetch retrieves a BoardGameGeek profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)

	c.logger.InfoContext(ctx, "fetching boardgamegeek profile", "url", urlStr, "username", username)

	// Try the XML API first
	apiURL := "https://boardgamegeek.com/xmlapi2/user?name=" + username
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpcache.UserAgent)

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err == nil {
		prof, parseErr := parseXML(body, urlStr, username)
		if parseErr == nil {
			return prof, nil
		}
	}

	// Fall back to HTML parsing from the profile page
	profileURL := "https://boardgamegeek.com/user/" + username
	htmlReq, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	htmlReq.Header.Set("User-Agent", httpcache.UserAgent)

	htmlBody, htmlErr := httpcache.FetchURL(ctx, c.cache, c.httpClient, htmlReq, c.logger)
	if htmlErr != nil {
		// Return minimal profile if both fail - graceful degradation
		//nolint:nilerr // graceful degradation: return partial profile on API/HTML failure
		return &profile.Profile{
			Platform:      platform,
			URL:           urlStr,
			Authenticated: false,
			Username:      username,
			DisplayName:   username,
			Fields:        make(map[string]string),
		}, nil
	}

	return parseHTML(htmlBody, profileURL, username), nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	prof := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		DisplayName:   username,
		Fields:        make(map[string]string),
	}

	// Extract display name from og:title
	ogTitle := htmlutil.OGTag(content, "og:title")
	if ogTitle != "" && !strings.Contains(strings.ToLower(ogTitle), "boardgamegeek") {
		prof.DisplayName = strings.TrimSpace(ogTitle)
	}

	// Extract avatar from og:image
	ogImage := htmlutil.OGTag(content, "og:image")
	if ogImage != "" {
		prof.AvatarURL = ogImage
	}

	// Try to extract location from page content
	locationPattern := regexp.MustCompile(`location[^>]*>([^<]+)</`)
	if m := locationPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Location = strings.TrimSpace(m[1])
	}

	// Extract social links
	for _, link := range htmlutil.SocialLinks(content) {
		if !strings.Contains(link, "boardgamegeek.com") {
			prof.SocialLinks = append(prof.SocialLinks, link)
		}
	}

	return prof
}

func parseXML(data []byte, urlStr, username string) (*profile.Profile, error) {
	var user userResponse
	if err := xml.Unmarshal(data, &user); err != nil {
		// If XML parsing fails, return minimal profile
		return &profile.Profile{
			Platform:      platform,
			URL:           urlStr,
			Authenticated: false,
			Username:      username,
			DisplayName:   username,
			Fields:        make(map[string]string),
		}, err
	}

	prof := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      user.Name,
		DisplayName:   user.Name,
		Fields:        make(map[string]string),
	}

	// Build display name from first/last name
	displayName := strings.TrimSpace(user.FirstName + " " + user.LastName)
	if displayName != "" {
		prof.DisplayName = displayName
	}

	// Set avatar URL
	if user.AvatarLink != "" && user.AvatarLink != "N/A" {
		prof.AvatarURL = user.AvatarLink
	}

	// Set location from state/province and country
	var locationParts []string
	if user.StateOrProv != "" {
		locationParts = append(locationParts, user.StateOrProv)
	}
	if user.Country != "" {
		locationParts = append(locationParts, user.Country)
	}
	if len(locationParts) > 0 {
		prof.Location = strings.Join(locationParts, ", ")
	}

	// Set website
	if user.WebAddress != "" {
		prof.Website = user.WebAddress
		prof.SocialLinks = append(prof.SocialLinks, user.WebAddress)
	}

	// Set created at from year registered
	if user.YearRegistered != "" {
		prof.CreatedAt = user.YearRegistered
		prof.Fields["year_registered"] = user.YearRegistered
	}

	// Set additional fields
	if user.ID != "" {
		prof.Fields["user_id"] = user.ID
	}
	if user.LastLogin != "" {
		prof.Fields["last_login"] = user.LastLogin
	}
	if user.TradeRating != "" {
		prof.Fields["trade_rating"] = user.TradeRating
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
