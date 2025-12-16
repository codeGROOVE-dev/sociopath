// Package hackerone fetches HackerOne profile data via GraphQL API.
package hackerone

import (
	"bytes"
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

const platform = "hackerone"

// platformInfo implements profile.Platform for HackerOne.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSecurity }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)hackerone\.com/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a HackerOne profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "hackerone.com/") {
		return false
	}
	// Skip non-profile pages
	skipPaths := []string{"/reports/", "/bugs/", "/programs/", "/settings/", "/directory/", "/leaderboard"}
	for _, sp := range skipPaths {
		if strings.Contains(lower, sp) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because HackerOne profiles are public.
func AuthRequired() bool { return false }

// Client handles HackerOne requests.
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

// New creates a HackerOne client.
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

// GraphQL query for user profile.
const userQuery = `query ($username: String!) {
  user(username: $username) {
    id
    username
    name
    bio
    website
    url
    created_at
    reputation
    signal
    impact
    rank
    resolved_report_count
    profile_picture(size: large)
    github_handle
    linkedin_handle
    twitter_handle
    bugcrowd_handle
    cobalt_handle
  }
}`

//nolint:govet // field alignment not critical for JSON parsing
type graphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

type graphQLResponse struct {
	Data struct {
		User *userData `json:"user"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

//nolint:govet // field alignment not critical for JSON parsing
type userData struct {
	ID                  string  `json:"id"`
	Username            string  `json:"username"`
	Name                string  `json:"name"`
	Bio                 string  `json:"bio"`
	Website             string  `json:"website"`
	URL                 string  `json:"url"`
	CreatedAt           string  `json:"created_at"`
	Reputation          int     `json:"reputation"`
	Signal              float64 `json:"signal"`
	Impact              float64 `json:"impact"`
	Rank                int     `json:"rank"`
	ResolvedReportCount int     `json:"resolved_report_count"`
	ProfilePicture      string  `json:"profile_picture"`
	GithubHandle        string  `json:"github_handle"`
	LinkedinHandle      string  `json:"linkedin_handle"`
	TwitterHandle       string  `json:"twitter_handle"`
	BugcrowdHandle      string  `json:"bugcrowd_handle"`
	CobaltHandle        string  `json:"cobalt_handle"`
}

// Fetch retrieves a HackerOne profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching hackerone profile", "url", urlStr, "username", username)

	// Build GraphQL request
	reqBody := graphQLRequest{
		Query: userQuery,
		Variables: map[string]any{
			"username": username,
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal graphql request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hackerone.com/graphql", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp graphQLResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse hackerone response: %w", err)
	}

	if len(resp.Errors) > 0 {
		return nil, fmt.Errorf("hackerone graphql error: %s", resp.Errors[0].Message)
	}

	if resp.Data.User == nil {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(resp.Data.User, urlStr), nil
}

func parseProfile(data *userData, profileURL string) *profile.Profile {
	prof := &profile.Profile{
		Platform:    platform,
		URL:         profileURL,
		Username:    data.Username,
		DisplayName: data.Name,
		Bio:         data.Bio,
		Fields:      make(map[string]string),
	}

	if data.ProfilePicture != "" {
		prof.AvatarURL = data.ProfilePicture
	}

	if data.Website != "" {
		prof.Website = data.Website
		prof.Fields["website"] = data.Website
		// Check if the website is a linktree link
		if strings.Contains(strings.ToLower(data.Website), "linktr.ee") {
			prof.SocialLinks = append(prof.SocialLinks, data.Website)
		}
	}

	// Store metrics
	if data.Reputation > 0 {
		prof.Fields["reputation"] = strconv.Itoa(data.Reputation)
	}
	if data.Signal > 0 {
		prof.Fields["signal"] = fmt.Sprintf("%.1f", data.Signal)
	}
	if data.Impact > 0 {
		prof.Fields["impact"] = fmt.Sprintf("%.1f", data.Impact)
	}
	if data.Rank > 0 {
		prof.Fields["rank"] = strconv.Itoa(data.Rank)
	}
	if data.ResolvedReportCount > 0 {
		prof.Fields["resolved_reports"] = strconv.Itoa(data.ResolvedReportCount)
	}

	// Extract join date
	if data.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, data.CreatedAt); err == nil {
			prof.Fields["joined"] = t.Format("January 2006")
		}
	}

	// Extract social links
	if data.GithubHandle != "" {
		socialURL := "https://github.com/" + data.GithubHandle
		prof.Fields["github"] = socialURL
		prof.SocialLinks = append(prof.SocialLinks, socialURL)
	}
	if data.LinkedinHandle != "" {
		socialURL := "https://linkedin.com/in/" + data.LinkedinHandle
		prof.Fields["linkedin"] = socialURL
		prof.SocialLinks = append(prof.SocialLinks, socialURL)
	}
	if data.TwitterHandle != "" {
		socialURL := "https://twitter.com/" + data.TwitterHandle
		prof.Fields["twitter"] = socialURL
		prof.SocialLinks = append(prof.SocialLinks, socialURL)
	}
	if data.BugcrowdHandle != "" {
		socialURL := "https://bugcrowd.com/" + data.BugcrowdHandle
		prof.Fields["bugcrowd"] = socialURL
		prof.SocialLinks = append(prof.SocialLinks, socialURL)
	}
	if data.CobaltHandle != "" {
		socialURL := "https://app.cobalt.io/researcher/" + data.CobaltHandle
		prof.Fields["cobalt"] = socialURL
		prof.SocialLinks = append(prof.SocialLinks, socialURL)
	}

	if prof.DisplayName == "" {
		prof.DisplayName = prof.Username
	}

	return prof
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		// Remove query parameters
		username := matches[1]
		if idx := strings.Index(username, "?"); idx > 0 {
			username = username[:idx]
		}
		return username
	}
	return ""
}
