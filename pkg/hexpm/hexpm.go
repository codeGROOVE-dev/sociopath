// Package hexpm fetches Hex.pm (Elixir/Erlang packages) user profile data.
package hexpm

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

const platform = "hexpm"

// platformInfo implements profile.Platform for Hex.pm.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypePackage }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)hex\.pm/users/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Hex.pm user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "hex.pm/users/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Hex.pm profiles are public.
func AuthRequired() bool { return false }

// Client handles Hex.pm requests.
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

// New creates a Hex.pm client.
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

// apiUser represents the Hex.pm user data.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type apiUser struct {
	Username string            `json:"username"`
	Email    string            `json:"email"`
	FullName string            `json:"full_name"`
	URL      string            `json:"url"`
	Handles  map[string]string `json:"handles"`
}

// Fetch retrieves a Hex.pm profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching hexpm profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://hex.pm/api/users/%s", username)

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

	var resp apiUser
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse hexpm response: %w", err)
	}

	if resp.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(&resp, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Username,
		Fields:   make(map[string]string),
	}

	if data.FullName != "" {
		p.Name = data.FullName
	} else {
		p.Name = data.Username
	}

	if data.Email != "" {
		p.Fields["email"] = data.Email
	}

	// Social handles (if present)
	for handleType, handleValue := range data.Handles {
		if handleValue == "" {
			continue
		}

		switch strings.ToLower(handleType) {
		case "github":
			githubURL := "https://github.com/" + handleValue
			p.Fields["github"] = githubURL
			p.SocialLinks = append(p.SocialLinks, githubURL)
		case "twitter":
			twitterURL := "https://twitter.com/" + handleValue
			p.Fields["twitter"] = twitterURL
			p.SocialLinks = append(p.SocialLinks, twitterURL)
		case "elixirforum":
			forumURL := "https://elixirforum.com/u/" + handleValue
			p.Fields["elixirforum"] = forumURL
			p.SocialLinks = append(p.SocialLinks, forumURL)
		case "freenode", "libera", "irc":
			p.Fields["irc"] = handleValue
		case "slack":
			p.Fields["slack"] = handleValue
		default:
			p.Fields[handleType] = handleValue
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
