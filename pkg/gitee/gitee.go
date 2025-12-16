// Package gitee fetches Gitee (Chinese GitHub) user profile data.
package gitee

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

const platform = "gitee"

// platformInfo implements profile.Platform for Gitee.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)gitee\.com/([a-zA-Z0-9_-]+)(?:/|$)`)

// Match returns true if the URL is a Gitee user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "gitee.com/") {
		return false
	}
	// Exclude repository URLs (have multiple path segments)
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) < 2 {
		return false
	}
	// Check it's not a reserved path
	reserved := []string{"explore", "enterprises", "gists", "events", "topics", "trending", "search", "api"}
	for _, r := range reserved {
		if strings.EqualFold(matches[1], r) {
			return false
		}
	}
	return true
}

// AuthRequired returns false because Gitee profiles are public.
func AuthRequired() bool { return false }

// Client handles Gitee requests.
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

// New creates a Gitee client.
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

// apiUser represents the Gitee API response.
type apiUser struct {
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
	Bio       string `json:"bio"`
	Blog      string `json:"blog"`
	Weibo     string `json:"weibo"`
	Company   string `json:"company"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
	HTMLURL   string `json:"html_url"`
}

// Fetch retrieves a Gitee profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching gitee profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://gitee.com/api/v5/users/%s", username)

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

	var user apiUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse gitee response: %w", err)
	}

	if user.Login == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(&user, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Login,
		Fields:   make(map[string]string),
	}

	if data.Name != "" {
		p.DisplayName = data.Name
	} else {
		p.DisplayName = data.Login
	}

	if data.Bio != "" {
		p.Bio = data.Bio
	}

	if data.AvatarURL != "" {
		p.AvatarURL = data.AvatarURL
	}

	// Parse creation date
	if data.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, data.CreatedAt); err == nil {
			p.CreatedAt = t.Format("2006-01-02")
		}
	}

	// Email
	if data.Email != "" {
		p.Fields["email"] = data.Email
	}

	// Company
	if data.Company != "" {
		p.Fields["company"] = data.Company
	}

	// Blog/website
	if data.Blog != "" {
		p.Fields["website"] = data.Blog
		p.SocialLinks = append(p.SocialLinks, data.Blog)
	}

	// Weibo (Chinese social media)
	if data.Weibo != "" {
		weiboURL := data.Weibo
		if !strings.HasPrefix(weiboURL, "http") {
			weiboURL = "https://weibo.com/" + weiboURL
		}
		p.Fields["weibo"] = weiboURL
		p.SocialLinks = append(p.SocialLinks, weiboURL)
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
