// Package rubygems fetches RubyGems.org profile data.
package rubygems

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

const platform = "rubygems"

// platformInfo implements profile.Platform for RubyGems.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypePackage }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)rubygems\.org/profiles/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a RubyGems profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "rubygems.org/profiles/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because RubyGems profiles are public.
func AuthRequired() bool { return false }

// Client handles RubyGems requests.
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

// New creates a RubyGems client.
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

// apiProfile represents the RubyGems profile API response.
type apiProfile struct {
	Handle string `json:"handle"`
	Email  string `json:"email"`
	ID     int    `json:"id"`
}

// apiGem represents a gem in the RubyGems API response.
//
//nolint:govet // fieldalignment not critical for JSON parsing
type apiGem struct {
	Name       string `json:"name"`
	Info       string `json:"info"`
	Downloads  int    `json:"downloads"`
	Version    string `json:"version"`
	ProjectURI string `json:"project_uri"`
}

// Fetch retrieves a RubyGems profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching rubygems profile", "url", urlStr, "username", username)

	// Fetch JSON API for email
	apiURL := fmt.Sprintf("https://rubygems.org/api/v1/profiles/%s.json", username)
	apiReq, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	apiReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	apiReq.Header.Set("Accept", "application/json")

	apiBody, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, apiReq, c.logger)
	if err != nil {
		return nil, err
	}

	var apiResp apiProfile
	if err := json.Unmarshal(apiBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse rubygems API response: %w", err)
	}

	if apiResp.Handle == "" {
		return nil, profile.ErrProfileNotFound
	}

	// Fetch HTML page for additional info (Twitter, avatar)
	htmlURL := fmt.Sprintf("https://rubygems.org/profiles/%s", username)
	htmlReq, err := http.NewRequestWithContext(ctx, http.MethodGet, htmlURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	htmlReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	htmlBody, htmlErr := httpcache.FetchURL(ctx, c.cache, c.httpClient, htmlReq, c.logger)

	// Fetch user's gems
	var gems []apiGem
	gemsURL := fmt.Sprintf("https://rubygems.org/api/v1/owners/%s/gems.json", username)
	gemsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, gemsURL, http.NoBody)
	if err == nil {
		gemsReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
		gemsReq.Header.Set("Accept", "application/json")
		gemsBody, gemsErr := httpcache.FetchURL(ctx, c.cache, c.httpClient, gemsReq, c.logger)
		if gemsErr == nil {
			_ = json.Unmarshal(gemsBody, &gems) //nolint:errcheck // best effort
		}
	}

	return parseProfile(&apiResp, string(htmlBody), htmlErr, gems, urlStr), nil
}

func parseProfile(api *apiProfile, html string, htmlErr error, gems []apiGem, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: api.Handle,
		Name:     api.Handle,
		Fields:   make(map[string]string),
	}

	if api.Email != "" {
		p.Fields["email"] = api.Email
	}

	// Parse HTML for additional info if available
	if htmlErr == nil && html != "" {
		// Extract Twitter handle
		twitterPattern := regexp.MustCompile(`href="https://twitter\.com/([^"]+)"`)
		if matches := twitterPattern.FindStringSubmatch(html); len(matches) > 1 {
			twitterHandle := matches[1]
			twitterURL := "https://twitter.com/" + twitterHandle
			p.Fields["twitter"] = twitterURL
			p.SocialLinks = append(p.SocialLinks, twitterURL)
		}

		// Extract avatar URL
		avatarPattern := regexp.MustCompile(`<img[^>]+id="profile_gravatar"[^>]+src="([^"]+)"`)
		if matches := avatarPattern.FindStringSubmatch(html); len(matches) > 1 {
			avatarURL := matches[1]
			// Make absolute URL if relative
			if strings.HasPrefix(avatarURL, "/") {
				avatarURL = "https://rubygems.org" + avatarURL
			}
			p.AvatarURL = avatarURL
		}

		// Extract GitHub link if present
		githubPattern := regexp.MustCompile(`href="(https://github\.com/[^"]+)"`)
		if matches := githubPattern.FindStringSubmatch(html); len(matches) > 1 {
			githubURL := matches[1]
			// Only add if it looks like a profile URL, not a repo
			if !strings.Contains(githubURL, "/rubygems") {
				p.Fields["github"] = githubURL
				p.SocialLinks = append(p.SocialLinks, githubURL)
			}
		}
	}

	// Add gems as posts
	for _, gem := range gems {
		post := profile.Post{
			Type:    profile.PostTypeRepository,
			Title:   fmt.Sprintf("%s %s", gem.Name, gem.Version),
			Content: gem.Info,
			URL:     gem.ProjectURI,
		}
		p.Posts = append(p.Posts, post)
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
