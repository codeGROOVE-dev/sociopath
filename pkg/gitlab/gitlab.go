// Package gitlab fetches GitLab profile data.
package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "gitlab"

// platformInfo implements profile.Platform for GitLab.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)gitlab\.com/([a-zA-Z0-9_.-]+)(?:/|$)`)

// Match returns true if the URL is a GitLab profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "gitlab.com/") {
		return false
	}
	// Exclude common non-profile paths
	excludePaths := []string{"/explore", "/dashboard", "/help", "/api/", "/groups/", "/-/"}
	for _, path := range excludePaths {
		if strings.Contains(lower, path) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because GitLab profiles are public.
func AuthRequired() bool { return false }

// Client handles GitLab requests.
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

// New creates a GitLab client.
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

// apiUser represents a GitLab user from the API.
//
//nolint:govet // field alignment not critical for JSON parsing
type apiUser struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	Name         string `json:"name"`
	State        string `json:"state"`
	AvatarURL    string `json:"avatar_url"`
	WebURL       string `json:"web_url"`
	Bio          string `json:"bio"`
	Location     string `json:"location"`
	PublicEmail  string `json:"public_email"`
	Website      string `json:"website_url"`
	Twitter      string `json:"twitter"`
	LinkedIn     string `json:"linkedin"`
	Skype        string `json:"skype"`
	JobTitle     string `json:"job_title"`
	Organization string `json:"organization"`
}

// Fetch retrieves a GitLab profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching gitlab profile", "url", urlStr, "username", username)

	// First, find the user ID by username
	apiURL := fmt.Sprintf("https://gitlab.com/api/v4/users?username=%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var users []apiUser
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, fmt.Errorf("failed to parse gitlab response: %w", err)
	}

	if len(users) == 0 {
		return nil, profile.ErrProfileNotFound
	}

	user := users[0]
	if user.State != "active" {
		return nil, profile.ErrProfileNotFound
	}

	// Fetch detailed user info (includes bio, location, etc.)
	detailURL := fmt.Sprintf("https://gitlab.com/api/v4/users/%d", user.ID)
	detailReq, err := http.NewRequestWithContext(ctx, http.MethodGet, detailURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	detailReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	detailReq.Header.Set("Accept", "application/json")

	detailBody, detailErr := httpcache.FetchURL(ctx, c.cache, c.httpClient, detailReq, c.logger)
	if detailErr != nil {
		// Fall back to basic info if detail fetch fails
		c.logger.DebugContext(ctx, "failed to fetch user details, using basic info", "error", detailErr)
		return parseProfile(&user, urlStr), nil
	}

	var detailedUser apiUser
	if unmarshalErr := json.Unmarshal(detailBody, &detailedUser); unmarshalErr != nil {
		// Fall back to basic info if parsing fails
		c.logger.DebugContext(ctx, "failed to parse user details, using basic info", "error", unmarshalErr)
		return parseProfile(&user, urlStr), nil
	}

	return parseProfile(&detailedUser, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Username,
		Name:     data.Name,
		Bio:      data.Bio,
		Location: data.Location,
		Fields:   make(map[string]string),
	}

	if data.AvatarURL != "" {
		p.AvatarURL = data.AvatarURL
	}

	if data.Website != "" {
		p.Website = data.Website
		p.SocialLinks = append(p.SocialLinks, data.Website)
	}

	if data.Twitter != "" {
		twitterURL := "https://twitter.com/" + data.Twitter
		p.Fields["twitter"] = twitterURL
		p.SocialLinks = append(p.SocialLinks, twitterURL)
	}

	if data.LinkedIn != "" {
		linkedinURL := "https://linkedin.com/in/" + data.LinkedIn
		p.Fields["linkedin"] = linkedinURL
		p.SocialLinks = append(p.SocialLinks, linkedinURL)
	}

	if data.PublicEmail != "" {
		p.Fields["email"] = data.PublicEmail
	}

	if data.JobTitle != "" {
		p.Fields["title"] = data.JobTitle
	}

	if data.Organization != "" {
		p.Fields["company"] = data.Organization
	}

	if p.Name == "" {
		p.Name = p.Username
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
