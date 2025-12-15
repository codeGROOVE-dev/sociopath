// Package hashnode fetches Hashnode user profile data.
package hashnode

import (
	"bytes"
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

const platform = "hashnode"

// platformInfo implements profile.Platform for Hashnode.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)hashnode\.com/@([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Hashnode user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "hashnode.com/@") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Hashnode profiles are public.
func AuthRequired() bool { return false }

// Client handles Hashnode requests.
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

// New creates a Hashnode client.
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

// graphQLRequest represents the GraphQL query structure.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type graphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

// graphQLResponse represents the GraphQL response structure.
type graphQLResponse struct {
	Data struct {
		User *apiUser `json:"user"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// apiUser represents the Hashnode user data.
type apiUser struct {
	Username       string `json:"username"`
	Name           string `json:"name"`
	ProfilePicture string `json:"profilePicture"`
	Tagline        string `json:"tagline"`
	Location       string `json:"location"`
	SocialMedia    struct {
		Twitter   string `json:"twitter"`
		GitHub    string `json:"github"`
		Website   string `json:"website"`
		LinkedIn  string `json:"linkedin"`
		YouTube   string `json:"youtube"`
		Instagram string `json:"instagram"`
		Facebook  string `json:"facebook"`
	} `json:"socialMediaLinks"`
}

const graphQLQuery = `
query User($username: String!) {
  user(username: $username) {
    username
    name
    profilePicture
    tagline
    location
    socialMediaLinks {
      twitter
      github
      website
      linkedin
      youtube
      instagram
      facebook
    }
  }
}
`

// Fetch retrieves a Hashnode profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching hashnode profile", "url", urlStr, "username", username)

	reqBody := graphQLRequest{
		Query: graphQLQuery,
		Variables: map[string]any{
			"username": username,
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://gql.hashnode.com/", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp graphQLResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse hashnode response: %w", err)
	}

	if len(resp.Errors) > 0 {
		return nil, fmt.Errorf("hashnode API error: %s", resp.Errors[0].Message)
	}

	if resp.Data.User == nil || resp.Data.User.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(resp.Data.User, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Username,
		Fields:   make(map[string]string),
	}

	if data.Name != "" {
		p.Name = data.Name
	} else {
		p.Name = data.Username
	}

	if data.Tagline != "" {
		p.Bio = data.Tagline
	}

	if data.ProfilePicture != "" {
		p.AvatarURL = data.ProfilePicture
	}

	if data.Location != "" {
		p.Location = data.Location
	}

	// Social links
	social := data.SocialMedia

	if social.Website != "" {
		p.Website = social.Website
		p.SocialLinks = append(p.SocialLinks, social.Website)
	}

	if social.GitHub != "" {
		githubURL := normalizeURL(social.GitHub, "https://github.com/")
		p.Fields["github"] = githubURL
		p.SocialLinks = append(p.SocialLinks, githubURL)
	}

	if social.Twitter != "" {
		twitterURL := normalizeURL(social.Twitter, "https://twitter.com/")
		p.Fields["twitter"] = twitterURL
		p.SocialLinks = append(p.SocialLinks, twitterURL)
	}

	if social.LinkedIn != "" {
		linkedinURL := normalizeURL(social.LinkedIn, "https://linkedin.com/in/")
		p.Fields["linkedin"] = linkedinURL
		p.SocialLinks = append(p.SocialLinks, linkedinURL)
	}

	if social.YouTube != "" {
		youtubeURL := normalizeURL(social.YouTube, "https://youtube.com/")
		p.Fields["youtube"] = youtubeURL
		p.SocialLinks = append(p.SocialLinks, youtubeURL)
	}

	if social.Instagram != "" {
		instagramURL := normalizeURL(social.Instagram, "https://instagram.com/")
		p.Fields["instagram"] = instagramURL
		p.SocialLinks = append(p.SocialLinks, instagramURL)
	}

	if social.Facebook != "" {
		facebookURL := normalizeURL(social.Facebook, "https://facebook.com/")
		p.Fields["facebook"] = facebookURL
		p.SocialLinks = append(p.SocialLinks, facebookURL)
	}

	return p
}

func normalizeURL(value, prefix string) string {
	if strings.HasPrefix(value, "http") {
		return value
	}
	return prefix + value
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
