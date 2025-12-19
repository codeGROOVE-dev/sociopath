// Package gitee fetches Gitee (Chinese GitHub) user profile data.
package gitee

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"slices"
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

func init() {
	profile.RegisterWithFetcher(platformInfo{}, fetchProfile)
}

// fetchProfile is the FetchFunc for Gitee profiles.
func fetchProfile(ctx context.Context, url string, cfg *profile.FetcherConfig) (*profile.Profile, error) {
	var opts []Option
	if cfg != nil {
		if cfg.Logger != nil {
			opts = append(opts, WithLogger(cfg.Logger))
		}
		if cfg.GiteeAccessToken != "" {
			opts = append(opts, WithAccessToken(cfg.GiteeAccessToken))
		}
		if c, ok := cfg.Cache.(httpcache.Cacher); ok {
			opts = append(opts, WithHTTPCache(c))
		}
	}
	client, err := New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

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
	httpClient  *http.Client
	cache       httpcache.Cacher
	logger      *slog.Logger
	accessToken string
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache       httpcache.Cacher
	logger      *slog.Logger
	accessToken string
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache httpcache.Cacher) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// WithAccessToken sets the Gitee API access token.
func WithAccessToken(token string) Option {
	return func(c *config) { c.accessToken = token }
}

// New creates a Gitee client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	logger := cfg.logger
	accessToken := cfg.accessToken

	// Try environment variables if no token provided
	if accessToken == "" {
		accessToken = os.Getenv("GITEE_ACCESS_TOKEN")
	}
	if accessToken == "" {
		accessToken = os.Getenv("GITEE_TOKEN")
	}

	// Try ~/.gitee file
	if accessToken == "" {
		if homeDir, err := os.UserHomeDir(); err == nil {
			tokenFile := homeDir + "/.gitee"
			if data, err := os.ReadFile(tokenFile); err == nil {
				accessToken = strings.TrimSpace(string(data))
				if accessToken != "" {
					logger.InfoContext(ctx, "using access token from ~/.gitee file")
				}
			}
		}
	}

	if accessToken == "" {
		logger.WarnContext(ctx, "GITEE_ACCESS_TOKEN not set - Gitee API requests will be rate-limited")
	} else if os.Getenv("GITEE_ACCESS_TOKEN") != "" {
		logger.InfoContext(ctx, "using GITEE_ACCESS_TOKEN for authenticated API requests")
	} else if os.Getenv("GITEE_TOKEN") != "" {
		logger.InfoContext(ctx, "using GITEE_TOKEN for authenticated API requests")
	}

	return &Client{
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		cache:       cfg.cache,
		logger:      logger,
		accessToken: accessToken,
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
	UpdatedAt string `json:"updated_at"`
	HTMLURL   string `json:"html_url"`

	// Statistics
	PublicRepos  int `json:"public_repos"`
	PublicGists  int `json:"public_gists"`
	Followers    int `json:"followers"`
	Following    int `json:"following"`
	Stared       int `json:"stared"` // Note: API typo, should be "starred"
	Watched      int `json:"watched"`

	// API URLs for additional data
	ReposURL         string `json:"repos_url"`
	OrganizationsURL string `json:"organizations_url"`
	EventsURL        string `json:"events_url"`
}

// apiRepo represents a Gitee repository response.
type apiRepo struct {
	Name            string `json:"name"`
	FullName        string `json:"full_name"`
	Description     string `json:"description"`
	HTMLURL         string `json:"html_url"`
	Language        string `json:"language"`
	StargazersCount int    `json:"stargazers_count"`
	ForksCount      int    `json:"forks_count"`
	Fork            bool   `json:"fork"`
}

// apiOrg represents a Gitee organization response.
type apiOrg struct {
	Login string `json:"login"`
	Name  string `json:"name"`
}

// Fetch retrieves a Gitee profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching gitee profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://gitee.com/api/v5/users/%s", username)
	if c.accessToken != "" {
		apiURL += "?access_token=" + c.accessToken
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Referer", "https://gitee.com/"+username)

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

	prof := parseProfile(&user, urlStr)

	// Fetch repositories
	if repos, err := c.fetchRepos(ctx, username); err == nil && len(repos) > 0 {
		prof.Repositories = repos
	}

	// Fetch organizations
	if orgs, err := c.fetchOrgs(ctx, username); err == nil && len(orgs) > 0 {
		slices.Sort(orgs)
		prof.Groups = orgs
	}

	return prof, nil
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

	// Parse update date
	if data.UpdatedAt != "" {
		if t, err := time.Parse(time.RFC3339, data.UpdatedAt); err == nil {
			p.UpdatedAt = t.Format("2006-01-02")
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

	// Statistics
	if data.PublicRepos > 0 {
		p.Fields["public_repos"] = fmt.Sprintf("%d", data.PublicRepos)
	}
	if data.PublicGists > 0 {
		p.Fields["public_gists"] = fmt.Sprintf("%d", data.PublicGists)
	}
	if data.Followers > 0 {
		p.Fields["followers"] = fmt.Sprintf("%d", data.Followers)
	}
	if data.Following > 0 {
		p.Fields["following"] = fmt.Sprintf("%d", data.Following)
	}
	if data.Stared > 0 {
		p.Fields["starred"] = fmt.Sprintf("%d", data.Stared)
	}
	if data.Watched > 0 {
		p.Fields["watched"] = fmt.Sprintf("%d", data.Watched)
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

// fetchRepos retrieves user's repositories.
func (c *Client) fetchRepos(ctx context.Context, username string) ([]profile.Repository, error) {
	apiURL := fmt.Sprintf("https://gitee.com/api/v5/users/%s/repos?sort=updated&per_page=20", username)
	if c.accessToken != "" {
		apiURL += "&access_token=" + c.accessToken
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Referer", "https://gitee.com/"+username)

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		c.logger.WarnContext(ctx, "failed to fetch repos", "error", err)
		return nil, nil // Non-fatal: return empty repos
	}

	var repos []apiRepo
	if err := json.Unmarshal(body, &repos); err != nil {
		c.logger.WarnContext(ctx, "failed to parse repos", "error", err)
		return nil, nil
	}

	var result []profile.Repository
	for _, repo := range repos {
		r := profile.Repository{
			Name:        repo.Name,
			Description: repo.Description,
			URL:         repo.HTMLURL,
			Language:    repo.Language,
		}
		if repo.StargazersCount > 0 {
			r.Stars = fmt.Sprintf("%d", repo.StargazersCount)
		}
		if repo.ForksCount > 0 {
			r.Forks = fmt.Sprintf("%d", repo.ForksCount)
		}
		result = append(result, r)
		if len(result) >= 10 {
			break // Limit to 10 repos
		}
	}

	return result, nil
}

// fetchOrgs retrieves user's organizations.
func (c *Client) fetchOrgs(ctx context.Context, username string) ([]string, error) {
	apiURL := fmt.Sprintf("https://gitee.com/api/v5/users/%s/orgs", username)
	if c.accessToken != "" {
		apiURL += "?access_token=" + c.accessToken
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Referer", "https://gitee.com/"+username)

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		c.logger.WarnContext(ctx, "failed to fetch orgs", "error", err)
		return nil, nil // Non-fatal: return empty orgs
	}

	var orgs []apiOrg
	if err := json.Unmarshal(body, &orgs); err != nil {
		c.logger.WarnContext(ctx, "failed to parse orgs", "error", err)
		return nil, nil
	}

	var result []string
	for _, org := range orgs {
		if org.Login != "" {
			result = append(result, org.Login)
		}
	}

	return result, nil
}
