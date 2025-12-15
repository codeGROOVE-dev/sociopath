// Package holopin fetches Holopin badge profile data.
package holopin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "holopin"

// platformInfo implements profile.Platform for Holopin.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSecurity }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)holopin\.io/@([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Holopin profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "holopin.io/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Holopin profiles are public.
func AuthRequired() bool { return false }

// Client handles Holopin requests.
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

// New creates a Holopin client.
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

// Next.js data structure embedded in HTML.
type nextData struct {
	Props struct {
		PageProps struct {
			User *userData `json:"user"`
		} `json:"pageProps"`
	} `json:"props"`
}

type userData struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Pronouns string `json:"pronouns"`
	Bio      string `json:"bio"`
	Website  string `json:"website"`
	Image    string `json:"image"`
	Twitter  string `json:"twitter"`
	GitHub   string `json:"github"`
	Discord  string `json:"discord"`
}

// Fetch retrieves a Holopin profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching holopin profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://www.holopin.io/@%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(ctx, body, urlStr, c.logger)
}

func parseHTML(ctx context.Context, body []byte, url string, logger *slog.Logger) (*profile.Profile, error) {
	// Extract __NEXT_DATA__ JSON from HTML
	htmlStr := string(body)
	const nextDataPrefix = `<script id="__NEXT_DATA__" type="application/json">`
	const nextDataSuffix = `</script>`

	startIdx := strings.Index(htmlStr, nextDataPrefix)
	if startIdx == -1 {
		return nil, errors.New("could not find __NEXT_DATA__ in holopin HTML")
	}
	startIdx += len(nextDataPrefix)

	endIdx := strings.Index(htmlStr[startIdx:], nextDataSuffix)
	if endIdx == -1 {
		return nil, errors.New("could not find end of __NEXT_DATA__ in holopin HTML")
	}

	jsonData := htmlStr[startIdx : startIdx+endIdx]

	var data nextData
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return nil, fmt.Errorf("failed to parse holopin __NEXT_DATA__: %w", err)
	}

	// Check if user exists - empty pageProps means user not found
	if data.Props.PageProps.User == nil || data.Props.PageProps.User.ID == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(ctx, data.Props.PageProps.User, url, logger), nil
}

func parseProfile(ctx context.Context, data *userData, profileURL string, logger *slog.Logger) *profile.Profile {
	prof := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: data.Username,
		Name:     data.Name,
		Bio:      data.Bio,
		Fields:   make(map[string]string),
	}

	if data.Image != "" {
		prof.AvatarURL = data.Image
	}

	if data.Website != "" {
		prof.Website = data.Website
		prof.Fields["website"] = data.Website
	}

	if data.Pronouns != "" {
		prof.Fields["pronouns"] = data.Pronouns
	}

	// Extract social links
	if data.GitHub != "" {
		githubURL := "https://github.com/" + data.GitHub
		logger.InfoContext(ctx, "discovered username from holopin",
			"platform", "github", "username", data.GitHub, "source", "holopin")
		prof.SocialLinks = append(prof.SocialLinks, githubURL)
		prof.Fields["github"] = githubURL
	}

	if data.Twitter != "" {
		twitterURL := "https://twitter.com/" + data.Twitter
		logger.InfoContext(ctx, "discovered username from holopin",
			"platform", "twitter", "username", data.Twitter, "source", "holopin")
		prof.SocialLinks = append(prof.SocialLinks, twitterURL)
		prof.Fields["twitter"] = twitterURL
	}

	if data.Discord != "" {
		prof.Fields["discord"] = data.Discord
	}

	// Default name to username if not provided
	if prof.Name == "" {
		prof.Name = prof.Username
	}

	return prof
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		username := matches[1]
		// Remove query parameters
		if idx := strings.Index(username, "?"); idx > 0 {
			username = username[:idx]
		}
		return username
	}
	return ""
}
