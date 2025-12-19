// Package openhub fetches OpenHub (formerly Ohloh) developer profile data.
// OpenHub tracks open-source developer contributions across projects.
package openhub

import (
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "openhub"

// platformInfo implements profile.Platform for OpenHub.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.RegisterWithFetcher(platformInfo{}, fetchProfile) }

var usernamePattern = regexp.MustCompile(`(?i)openhub\.net/(?:accounts|p)/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is an OpenHub profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return (strings.Contains(lower, "openhub.net/accounts/") ||
		strings.Contains(lower, "openhub.net/p/")) &&
		usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because OpenHub profiles are public.
func AuthRequired() bool { return false }

// Client handles OpenHub requests.
type Client struct {
	httpClient *http.Client
	cache      httpcache.Cacher
	logger     *slog.Logger
	apiKey     string
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache  httpcache.Cacher
	logger *slog.Logger
	apiKey string
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache httpcache.Cacher) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// WithAPIKey sets the OpenHub API key (optional but recommended).
func WithAPIKey(apiKey string) Option {
	return func(c *config) { c.apiKey = apiKey }
}

// New creates an OpenHub client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
		apiKey:     cfg.apiKey,
	}, nil
}

// OpenHub XML API response structures

// Response is the root element of OpenHub API responses.
type Response struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status"`
	Result  *Result  `xml:"result"`
	Error   string   `xml:"error"`
}

// Result contains the account data.
type Result struct {
	Account *Account `xml:"account"`
}

// Account represents an OpenHub account.
//
//nolint:govet // fieldalignment: struct ordering for XML readability
type Account struct {
	ID             int        `xml:"id"`
	Name           string     `xml:"name"`
	Email          string     `xml:"email"`
	AboutRaw       string     `xml:"about_raw"`
	AvatarURL      string     `xml:"avatar_url"`
	CountryCode    string     `xml:"country_code"`
	Location       string     `xml:"location"`
	Latitude       string     `xml:"latitude"`
	Longitude      string     `xml:"longitude"`
	URL            string     `xml:"url"`
	HTMLURL        string     `xml:"html_url"`
	CreatedAt      string     `xml:"created_at"`
	UpdatedAt      string     `xml:"updated_at"`
	HomepageURL    string     `xml:"homepage_url"`
	TwitterAccount string     `xml:"twitter_account"`
	KudoRank       int        `xml:"kudo_rank"`
	KudoScore      *KudoScore `xml:"kudo_score"`
	Posts          *Posts     `xml:"posts"`
}

// KudoScore represents kudos metrics.
type KudoScore struct {
	KudoRank int `xml:"kudo_rank"`
	Position int `xml:"position"`
	Created  int `xml:"created"`
	Received int `xml:"received"`
}

// Posts represents post counts.
type Posts struct {
	Count int `xml:"count,attr"`
}

// Fetch retrieves an OpenHub profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching openhub profile", "url", urlStr, "username", username)

	// Try API first (if we have an API key or even without - some endpoints are public)
	apiResp, err := c.fetchFromAPI(ctx, username)
	if err == nil && apiResp != nil {
		return apiResp, nil
	}

	c.logger.InfoContext(ctx, "api fetch failed, falling back to HTML", "error", err)

	// Fall back to HTML parsing
	return c.fetchFromHTML(ctx, urlStr, username)
}

func (c *Client) fetchFromAPI(ctx context.Context, username string) (*profile.Profile, error) {
	// OpenHub API URL
	apiURL := fmt.Sprintf("https://www.openhub.net/accounts/%s.xml", username)
	if c.apiKey != "" {
		apiURL += "?api_key=" + c.apiKey
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "application/xml")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp Response
	if err := xml.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse XML response: %w", err)
	}

	if resp.Status != "success" {
		return nil, fmt.Errorf("API returned error: %s", resp.Error)
	}

	if resp.Result == nil || resp.Result.Account == nil {
		return nil, profile.ErrProfileNotFound
	}

	return parseAPIProfile(resp.Result.Account), nil
}

func (c *Client) fetchFromHTML(ctx context.Context, urlStr, username string) (*profile.Profile, error) {
	// Construct HTML URL
	htmlURL := fmt.Sprintf("https://www.openhub.net/accounts/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, htmlURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTMLProfile(body, htmlURL, username)
}

func parseAPIProfile(data *Account) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         data.HTMLURL,
		Username:    data.Name,
		DisplayName: data.Name,
		Bio:         data.AboutRaw,
		Location:    data.Location,
		AvatarURL:   data.AvatarURL,
		Website:     data.HomepageURL,
		CreatedAt:   data.CreatedAt,
		UpdatedAt:   data.UpdatedAt,
		Fields:      make(map[string]string),
	}

	if data.Email != "" {
		// p.Emails = append(p.Emails, data.Email)
	}

	if data.HomepageURL != "" {
		p.SocialLinks = append(p.SocialLinks, data.HomepageURL)
	}

	if data.TwitterAccount != "" {
		twitterURL := fmt.Sprintf("https://twitter.com/%s", data.TwitterAccount)
		p.SocialLinks = append(p.SocialLinks, twitterURL)
		p.Fields["twitter"] = data.TwitterAccount
	}

	if data.CountryCode != "" {
		p.Fields["country"] = data.CountryCode
	}

	if data.KudoRank > 0 {
		p.Fields["kudo_rank"] = fmt.Sprintf("%d", data.KudoRank)
	}

	if data.KudoScore != nil {
		if data.KudoScore.Created > 0 {
			p.Fields["kudos_created"] = fmt.Sprintf("%d", data.KudoScore.Created)
		}
		if data.KudoScore.Received > 0 {
			p.Fields["kudos_received"] = fmt.Sprintf("%d", data.KudoScore.Received)
		}
		if data.KudoScore.Position > 0 {
			p.Fields["global_position"] = fmt.Sprintf("%d", data.KudoScore.Position)
		}
	}

	if data.Posts != nil && data.Posts.Count > 0 {
		p.Fields["posts"] = fmt.Sprintf("%d", data.Posts.Count)
	}

	return p
}

func parseHTMLProfile(body []byte, profileURL, username string) (*profile.Profile, error) {
	p := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: username,
		Fields:   make(map[string]string),
	}

	html := string(body)

	// Extract avatar
	avatarPattern := regexp.MustCompile(`<img[^>]+class="[^"]*account_avatar[^"]*"[^>]+src="([^"]+)"`)
	if matches := avatarPattern.FindStringSubmatch(html); len(matches) > 1 {
		p.AvatarURL = matches[1]
	}

	// Extract bio
	bioPattern := regexp.MustCompile(`(?s)<div[^>]+class="[^"]*about[^"]*"[^>]*>(.*?)</div>`)
	if matches := bioPattern.FindStringSubmatch(html); len(matches) > 1 {
		p.Bio = htmlutil.StripTags(matches[1])
		p.Bio = strings.TrimSpace(p.Bio)
	}

	// Extract location
	locationPattern := regexp.MustCompile(`<i[^>]+class="[^"]*fa-map-marker[^"]*"[^>]*></i>\s*([^<]+)`)
	if matches := locationPattern.FindStringSubmatch(html); len(matches) > 1 {
		p.Location = strings.TrimSpace(matches[1])
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(html)

	// Extract emails
	emails := htmlutil.EmailAddresses(html)
	if len(emails) > 0 {
		p.Fields["email"] = emails[0]
	}

	if p.DisplayName == "" {
		p.DisplayName = username
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

// fetchProfile is the FetchFunc wrapper for profile registration.
func fetchProfile(ctx context.Context, url string, cfg *profile.FetcherConfig) (*profile.Profile, error) {
	var opts []Option
	if cfg != nil {
		if cfg.Logger != nil {
			opts = append(opts, WithLogger(cfg.Logger))
		}
		if c, ok := cfg.Cache.(httpcache.Cacher); ok {
			opts = append(opts, WithHTTPCache(c))
		}
		// Note: API key would need to be added to FetcherConfig if we want to support it
	}

	client, err := New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return client.Fetch(ctx, url)
}
