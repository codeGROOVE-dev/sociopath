// Package gitlab fetches GitLab profile data.
package gitlab

import (
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

const platform = "gitlab"

// platformInfo implements profile.Platform for GitLab.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var (
	usernamePattern    = regexp.MustCompile(`(?i)gitlab\.com/([a-zA-Z0-9_.-]+)(?:/|$)`)
	memberSincePattern = regexp.MustCompile(`Member since ([A-Za-z]+ \d{1,2}, \d{4})`)
	bioPattern         = regexp.MustCompile(`(?s)profile-user-bio[^>]*>\s*([^<]+)\s*</p>`)
	locationPattern    = regexp.MustCompile(`(?s)addressLocality">\s*([^<]+)\s*</span>`)
	jobTitlePattern    = regexp.MustCompile(`itemprop="jobTitle">([^<]+)</span>`)
	websitePattern     = regexp.MustCompile(`itemprop="url" href="([^"]+)">`)
	twitterPattern     = regexp.MustCompile(`href="https://twitter\.com/([^"]+)">[^<]+</a>`)
	utcOffsetPattern   = regexp.MustCompile(`data-utc-offset="(-?\d+)"`)
)

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

// apiUser represents a GitLab user from the search API.
// Bio, location, and created_at are fetched from HTML since they require auth via API.
type apiUser struct {
	Username  string `json:"username"`
	Name      string `json:"name"`
	State     string `json:"state"`
	AvatarURL string `json:"avatar_url"`
}

type apiProject struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	WebURL      string `json:"web_url"`
	StarCount   int    `json:"star_count"`
	ForksCount  int    `json:"forks_count"`
}

// Fetch retrieves a GitLab profile.
func (c *Client) Fetch(ctx context.Context, url string) (*profile.Profile, error) {
	m := usernamePattern.FindStringSubmatch(url)
	if len(m) < 2 {
		return nil, fmt.Errorf("could not extract username from URL: %s", url)
	}
	user := m[1]

	c.logger.InfoContext(ctx, "fetching gitlab profile", "url", url, "username", user)

	// Fetch user from API
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://gitlab.com/api/v4/users?username="+user, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpcache.UserAgent)
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var users []apiUser
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, fmt.Errorf("failed to parse gitlab response: %w", err)
	}
	if len(users) == 0 || users[0].State != "active" {
		return nil, profile.ErrProfileNotFound
	}

	p := buildProfile(&users[0], url)

	// Fetch HTML for additional profile data (not available via API without auth)
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "https://gitlab.com/"+user, http.NoBody)
	if err == nil {
		req.Header.Set("User-Agent", httpcache.UserAgent)
		if body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger); err == nil {
			parseHTMLProfile(string(body), p)
		}
	}

	// Fetch user's projects
	req, err = http.NewRequestWithContext(ctx, http.MethodGet,
		"https://gitlab.com/api/v4/users/"+user+"/projects?per_page=6&order_by=updated_at", http.NoBody)
	if err == nil {
		req.Header.Set("User-Agent", httpcache.UserAgent)
		req.Header.Set("Accept", "application/json")
		if body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger); err == nil {
			var projects []apiProject
			if json.Unmarshal(body, &projects) == nil {
				for _, proj := range projects {
					repo := profile.Repository{
						Name:        proj.Name,
						Description: proj.Description,
						URL:         proj.WebURL,
					}
					if proj.StarCount > 0 {
						repo.Stars = strconv.Itoa(proj.StarCount)
					}
					if proj.ForksCount > 0 {
						repo.Forks = strconv.Itoa(proj.ForksCount)
					}
					p.Repositories = append(p.Repositories, repo)
				}
			}
		}
	}

	return p, nil
}

func buildProfile(u *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:  platform,
		URL:       url,
		Username:  u.Username,
		Name:      u.Name,
		AvatarURL: u.AvatarURL,
		Fields:    make(map[string]string),
	}
	if p.Name == "" {
		p.Name = p.Username
	}
	return p
}

func parseHTMLProfile(html string, p *profile.Profile) {
	if m := memberSincePattern.FindStringSubmatch(html); len(m) > 1 {
		if t, err := time.Parse("January 2, 2006", m[1]); err == nil {
			p.CreatedAt = t.Format("2006-01-02")
		}
	}
	if m := bioPattern.FindStringSubmatch(html); len(m) > 1 {
		if s := strings.TrimSpace(m[1]); s != "" {
			p.Bio = s
		}
	}
	if m := locationPattern.FindStringSubmatch(html); len(m) > 1 {
		if s := strings.TrimSpace(m[1]); s != "" {
			p.Location = s
		}
	}
	if m := jobTitlePattern.FindStringSubmatch(html); len(m) > 1 {
		if s := strings.TrimSpace(m[1]); s != "" {
			p.Fields["title"] = s
		}
	}
	if m := websitePattern.FindStringSubmatch(html); len(m) > 1 {
		p.Website = m[1]
		p.SocialLinks = append(p.SocialLinks, m[1])
	}
	if m := twitterPattern.FindStringSubmatch(html); len(m) > 1 {
		url := "https://twitter.com/" + m[1]
		p.Fields["twitter"] = url
		p.SocialLinks = append(p.SocialLinks, url)
	}
	if m := utcOffsetPattern.FindStringSubmatch(html); len(m) > 1 {
		if sec, err := strconv.Atoi(m[1]); err == nil {
			hrs := float64(sec) / 3600.0
			p.UTCOffset = &hrs
		}
	}
}
