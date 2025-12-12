// Package velog fetches Velog (Korean dev blog) user profile data.
package velog

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

const platform = "velog"

var usernamePattern = regexp.MustCompile(`(?i)velog\.io/@([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Velog user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "velog.io/@") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Velog profiles are public.
func AuthRequired() bool { return false }

// Client handles Velog requests.
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

// New creates a Velog client.
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

// profileLinks represents the social links in a Velog profile.
type profileLinks struct {
	URL      string `json:"url"`
	Email    string `json:"email"`
	GitHub   string `json:"github"`
	Twitter  string `json:"twitter"`
	Facebook string `json:"facebook"`
}

// apiUser represents the Velog user data.
type apiUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Profile  struct {
		DisplayName  string       `json:"display_name"`
		ShortBio     string       `json:"short_bio"`
		Thumbnail    string       `json:"thumbnail"`
		About        string       `json:"about"`
		ProfileLinks profileLinks `json:"profile_links"`
	} `json:"profile"`
}

const graphQLQuery = `
query User($username: String!) {
  user(username: $username) {
    id
    username
    profile {
      display_name
      short_bio
      thumbnail
      about
      profile_links
    }
  }
}
`

// Fetch retrieves a Velog profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching velog profile", "url", urlStr, "username", username)

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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.velog.io/graphql", bytes.NewReader(jsonBody))
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
		return nil, fmt.Errorf("failed to parse velog response: %w", err)
	}

	if len(resp.Errors) > 0 {
		return nil, fmt.Errorf("velog API error: %s", resp.Errors[0].Message)
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

	// Display name
	if data.Profile.DisplayName != "" {
		p.Name = data.Profile.DisplayName
	} else {
		p.Name = data.Username
	}

	// Bio - prefer short_bio, fallback to about
	if data.Profile.ShortBio != "" {
		p.Bio = data.Profile.ShortBio
	} else if data.Profile.About != "" {
		p.Bio = data.Profile.About
	}

	// Avatar
	if data.Profile.Thumbnail != "" {
		p.AvatarURL = data.Profile.Thumbnail
	}

	// Profile links
	links := data.Profile.ProfileLinks

	if links.Email != "" {
		p.Fields["email"] = links.Email
	}

	if links.URL != "" {
		p.Fields["website"] = links.URL
		p.SocialLinks = append(p.SocialLinks, links.URL)
	}

	if links.GitHub != "" {
		githubURL := links.GitHub
		if !strings.HasPrefix(githubURL, "http") {
			githubURL = "https://github.com/" + githubURL
		}
		p.Fields["github"] = githubURL
		p.SocialLinks = append(p.SocialLinks, githubURL)
	}

	if links.Twitter != "" {
		twitterURL := links.Twitter
		if !strings.HasPrefix(twitterURL, "http") {
			twitterURL = "https://twitter.com/" + twitterURL
		}
		p.Fields["twitter"] = twitterURL
		p.SocialLinks = append(p.SocialLinks, twitterURL)
	}

	if links.Facebook != "" {
		facebookURL := links.Facebook
		if !strings.HasPrefix(facebookURL, "http") {
			facebookURL = "https://facebook.com/" + facebookURL
		}
		p.Fields["facebook"] = facebookURL
		p.SocialLinks = append(p.SocialLinks, facebookURL)
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
