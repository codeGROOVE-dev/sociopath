// Package linuxquestions fetches LinuxQuestions.org forum profile data.
package linuxquestions

import (
	"context"
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

const platform = "linuxquestions"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return false }

func init() { profile.RegisterWithFetcher(platformInfo{}, fetchProfile) }

var userIDPattern = regexp.MustCompile(`member\.php\?u=(\d+)`)

func Match(urlStr string) bool {
	return strings.Contains(urlStr, "linuxquestions.org/questions/member.php") &&
		userIDPattern.MatchString(urlStr)
}

type Client struct {
	httpClient *http.Client
	cache      httpcache.Cacher
	logger     *slog.Logger
}

type Option func(*config)
type config struct {
	cache  httpcache.Cacher
	logger *slog.Logger
}

func WithHTTPCache(c httpcache.Cacher) Option { return func(cfg *config) { cfg.cache = c } }
func WithLogger(l *slog.Logger) Option        { return func(cfg *config) { cfg.logger = l } }

func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}
	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	userID := extractUserID(urlStr)
	if userID == "" {
		return nil, fmt.Errorf("could not extract user ID from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching linuxquestions profile", "url", urlStr, "user_id", userID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, urlStr, userID)
}

func parseProfile(body []byte, profileURL, userID string) (*profile.Profile, error) {
	html := string(body)
	p := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Fields:   make(map[string]string),
	}

	// Extract username
	usernameRe := regexp.MustCompile(`<title>([^<]+) - LinuxQuestions\.org</title>`)
	if matches := usernameRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Username = strings.TrimSpace(matches[1])
		p.DisplayName = p.Username
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`<img[^>]+src="([^"]+)"[^>]+alt="(?:[^"]*avatar[^"]*)"`)
	if matches := avatarRe.FindStringSubmatch(html); len(matches) > 1 {
		p.AvatarURL = matches[1]
	}

	// Extract profile fields from vBulletin fieldsets
	locationRe := regexp.MustCompile(`(?i)<dt>Location</dt>\s*<dd>([^<]+)</dd>`)
	if matches := locationRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Location = strings.TrimSpace(matches[1])
	}

	interestsRe := regexp.MustCompile(`(?i)<dt>Interests</dt>\s*<dd>([^<]+)</dd>`)
	if matches := interestsRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Bio = strings.TrimSpace(matches[1])
	}

	occupationRe := regexp.MustCompile(`(?i)<dt>Occupation</dt>\s*<dd>([^<]+)</dd>`)
	if matches := occupationRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["occupation"] = strings.TrimSpace(matches[1])
	}

	homepageRe := regexp.MustCompile(`(?i)<dt>Home Page</dt>\s*<dd><a href="([^"]+)"`)
	if matches := homepageRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Website = strings.TrimSpace(matches[1])
		p.SocialLinks = append(p.SocialLinks, p.Website)
	}

	// Extract join date
	joinRe := regexp.MustCompile(`(?i)<dt>Join Date</dt>\s*<dd>([^<]+)</dd>`)
	if matches := joinRe.FindStringSubmatch(html); len(matches) > 1 {
		p.CreatedAt = strings.TrimSpace(matches[1])
	}

	// Extract post count
	postsRe := regexp.MustCompile(`(?i)<dt>Total Posts</dt>\s*<dd>([0-9,]+)</dd>`)
	if matches := postsRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["total_posts"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract social links and emails
	for _, link := range htmlutil.SocialLinks(html) {
		if !contains(p.SocialLinks, link) {
			p.SocialLinks = append(p.SocialLinks, link)
		}
	}
	emails := htmlutil.EmailAddresses(html)
	if len(emails) > 0 {
		p.Fields["email"] = emails[0]
	}

	return p, nil
}

func extractUserID(urlStr string) string {
	matches := userIDPattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

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
