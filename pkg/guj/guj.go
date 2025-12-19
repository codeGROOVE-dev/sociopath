// Package guj fetches GUJ (Grupo de Usuarios Java) user profile data.
package guj

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "guj"

// Pre-compiled patterns for parsing GUJ data.
var (
	usernameRE = regexp.MustCompile(`guj\.com\.br/u/([^/?#]+)`)
)

// platformInfo implements profile.Platform for GUJ.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() {
	profile.RegisterWithFetcher(platformInfo{}, fetchProfile)
}

// fetchProfile is the FetchFunc for GUJ profiles.
func fetchProfile(ctx context.Context, url string, cfg *profile.FetcherConfig) (*profile.Profile, error) {
	var opts []Option
	if cfg != nil {
		if cfg.Logger != nil {
			opts = append(opts, WithLogger(cfg.Logger))
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

// Match returns true if the URL is a GUJ profile URL.
func Match(url string) bool {
	lower := strings.ToLower(url)
	return strings.Contains(lower, "guj.com.br/u/")
}

// AuthRequired returns false because GUJ profiles are public.
func AuthRequired() bool { return false }

// Client handles GUJ requests.
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

// New creates a GUJ client.
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

// Fetch retrieves a GUJ profile.
func (c *Client) Fetch(ctx context.Context, url string) (*profile.Profile, error) {
	username := extractUsername(url)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", url)
	}

	normalizedURL := fmt.Sprintf("https://www.guj.com.br/u/%s", username)
	c.logger.InfoContext(ctx, "fetching guj profile", "url", normalizedURL, "username", username)

	// Try JSON API first (Discourse-style)
	apiURL := fmt.Sprintf("%s.json", normalizedURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err == nil {
		p, parseErr := parseJSONProfile(body, normalizedURL, username)
		if parseErr == nil {
			return p, nil
		}
		c.logger.Debug("failed to parse JSON, falling back to HTML", "error", parseErr)
	}

	// Fallback to HTML parsing
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err = httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTMLProfile(string(body), normalizedURL, username)
}

// discourseUser represents Discourse user API response.
type discourseUser struct {
	User struct {
		ID              int    `json:"id"`
		Username        string `json:"username"`
		Name            string `json:"name"`
		AvatarTemplate  string `json:"avatar_template"`
		Bio             string `json:"bio_raw"`
		BioCooked       string `json:"bio_cooked"`
		Location        string `json:"location"`
		Website         string `json:"website_name"`
		CreatedAt       string `json:"created_at"`
		LastSeenAt      string `json:"last_seen_at"`
		PostCount       int    `json:"post_count"`
		TopicCount      int    `json:"topic_count"`
		LikesGiven      int    `json:"likes_given"`
		LikesReceived   int    `json:"likes_received"`
		DaysVisited     int    `json:"days_visited"`
	} `json:"user"`
}

func parseJSONProfile(data []byte, url, username string) (*profile.Profile, error) {
	var userData discourseUser
	if err := json.Unmarshal(data, &userData); err != nil {
		return nil, err
	}

	u := userData.User
	if u.ID == 0 {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    username,
		DisplayName: u.Name,
		Bio:         u.Bio,
		Location:    u.Location,
		Website:     u.Website,
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.LastSeenAt,
		Fields:      make(map[string]string),
	}

	if p.DisplayName == "" {
		p.DisplayName = username
	}

	// Extract avatar URL
	if u.AvatarTemplate != "" {
		// Discourse avatar template: replace {size} with actual size
		avatarURL := strings.ReplaceAll(u.AvatarTemplate, "{size}", "240")
		if strings.HasPrefix(avatarURL, "/") {
			avatarURL = "https://www.guj.com.br" + avatarURL
		}
		p.AvatarURL = avatarURL
	}

	// Add statistics
	if u.PostCount > 0 {
		p.Fields["post_count"] = fmt.Sprintf("%d", u.PostCount)
	}
	if u.TopicCount > 0 {
		p.Fields["topic_count"] = fmt.Sprintf("%d", u.TopicCount)
	}
	if u.LikesReceived > 0 {
		p.Fields["likes_received"] = fmt.Sprintf("%d", u.LikesReceived)
	}
	if u.LikesGiven > 0 {
		p.Fields["likes_given"] = fmt.Sprintf("%d", u.LikesGiven)
	}
	if u.DaysVisited > 0 {
		p.Fields["days_visited"] = fmt.Sprintf("%d", u.DaysVisited)
	}

	// Extract social links from bio
	if p.Bio != "" {
		p.SocialLinks = htmlutil.SocialLinks(p.Bio)
	}

	// Also extract from BioCooked HTML
	if u.BioCooked != "" {
		for _, link := range htmlutil.SocialLinks(u.BioCooked) {
			if !strings.Contains(link, "guj.com.br") {
				alreadyAdded := false
				for _, existing := range p.SocialLinks {
					if existing == link {
						alreadyAdded = true
						break
					}
				}
				if !alreadyAdded {
					p.SocialLinks = append(p.SocialLinks, link)
				}
			}
		}
	}

	return p, nil
}

func parseHTMLProfile(html, url, username string) (*profile.Profile, error) {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract name from title
	p.PageTitle = htmlutil.Title(html)
	if p.PageTitle != "" {
		name := strings.TrimSuffix(p.PageTitle, " - GUJ")
		name = strings.TrimSpace(name)
		p.DisplayName = name
	}
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	// Extract bio
	p.Bio = htmlutil.Description(html)

	// Extract avatar from og:image or user-avatar
	avatarPattern := regexp.MustCompile(`user_avatar/[^"'\s]+\.(?:png|jpg|jpeg|gif)`)
	if m := avatarPattern.FindString(html); m != "" {
		p.AvatarURL = "https://www.guj.com.br/" + m
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(html)
	var filtered []string
	for _, link := range p.SocialLinks {
		if !strings.Contains(link, "guj.com.br") {
			filtered = append(filtered, link)
		}
	}
	p.SocialLinks = filtered

	return p, nil
}

func extractUsername(url string) string {
	if m := usernameRE.FindStringSubmatch(url); len(m) > 1 {
		return m[1]
	}
	return ""
}
