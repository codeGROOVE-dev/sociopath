// Package twitch fetches Twitch streamer profile data.
package twitch

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

const platform = "twitch"

// platformInfo implements profile.Platform for Twitch.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeVideo }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Public Client-ID used by Twitch's own web client.
const twitchClientID = "kimne78kx3ncx6brgo4mv6wki5h1ko"

var usernamePattern = regexp.MustCompile(`(?i)(?:twitch\.tv|go\.twitch\.tv)/([a-zA-Z0-9_]+)`)

// Match returns true if the URL is a Twitch profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "twitch.tv/") {
		return false
	}
	// Exclude non-profile paths
	excluded := []string{"/directory", "/videos/", "/clip/", "/settings", "/downloads", "/jobs", "/p/", "/broadcast/"}
	for _, ex := range excluded {
		if strings.Contains(lower, ex) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Twitch public profiles don't require auth.
func AuthRequired() bool { return false }

// Client handles Twitch requests.
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

// New creates a Twitch client.
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

const graphQLQuery = `query($login: String!) {
  user(login: $login) {
    id
    login
    displayName
    description
    createdAt
    profileImageURL(width: 300)
    bannerImageURL
    roles {
      isPartner
      isAffiliate
    }
    channel {
      socialMedias {
        name
        url
      }
    }
  }
}`

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

// apiUser represents the Twitch user data.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type apiUser struct {
	ID              string `json:"id"`
	Login           string `json:"login"`
	DisplayName     string `json:"displayName"`
	Description     string `json:"description"`
	CreatedAt       string `json:"createdAt"`
	ProfileImageURL string `json:"profileImageURL"`
	BannerImageURL  string `json:"bannerImageURL"`
	Roles           struct {
		IsPartner   bool `json:"isPartner"`
		IsAffiliate bool `json:"isAffiliate"`
	} `json:"roles"`
	Channel struct {
		SocialMedias []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"socialMedias"`
	} `json:"channel"`
}

// Fetch retrieves a Twitch profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching twitch profile", "url", urlStr, "username", username)

	reqBody := graphQLRequest{
		Query: graphQLQuery,
		Variables: map[string]any{
			"login": strings.ToLower(username),
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://gql.twitch.tv/gql", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Client-Id", twitchClientID)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp graphQLResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse twitch response: %w", err)
	}

	if len(resp.Errors) > 0 {
		return nil, fmt.Errorf("twitch API error: %s", resp.Errors[0].Message)
	}

	if resp.Data.User == nil || resp.Data.User.Login == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(resp.Data.User, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Login,
		Fields:   make(map[string]string),
	}

	if data.DisplayName != "" {
		p.DisplayName = data.DisplayName
	} else {
		p.DisplayName = data.Login
	}

	if data.Description != "" {
		p.Bio = data.Description
	}

	if data.ProfileImageURL != "" {
		p.AvatarURL = data.ProfileImageURL
	}

	if data.CreatedAt != "" {
		p.CreatedAt = data.CreatedAt
	}

	// Partner/Affiliate status
	if data.Roles.IsPartner {
		p.Badges = map[string]string{"Partner": "1"}
	} else if data.Roles.IsAffiliate {
		p.Badges = map[string]string{"Affiliate": "1"}
	}

	// Social links
	for _, social := range data.Channel.SocialMedias {
		if social.URL == "" {
			continue
		}

		nameLower := strings.ToLower(social.Name)
		switch nameLower {
		case "twitter", "x":
			p.Fields["twitter"] = social.URL
			p.SocialLinks = append(p.SocialLinks, social.URL)
		case "instagram":
			p.Fields["instagram"] = social.URL
			p.SocialLinks = append(p.SocialLinks, social.URL)
		case "youtube":
			p.Fields["youtube"] = social.URL
			p.SocialLinks = append(p.SocialLinks, social.URL)
		case "tiktok":
			p.Fields["tiktok"] = social.URL
			p.SocialLinks = append(p.SocialLinks, social.URL)
		case "discord":
			p.Fields["discord"] = social.URL
			p.SocialLinks = append(p.SocialLinks, social.URL)
		case "facebook":
			p.Fields["facebook"] = social.URL
			p.SocialLinks = append(p.SocialLinks, social.URL)
		default:
			// Generic social link
			p.SocialLinks = append(p.SocialLinks, social.URL)
		}
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
