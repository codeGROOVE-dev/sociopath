package ringzer0

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "ringzer0"

var usernamePattern = regexp.MustCompile(`(?i)ringzer0ctf\.com/profile/(\d+)/([a-zA-Z0-9_-]+)`)

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSecurity }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return false }

func init() { profile.Register(platformInfo{}) }

type Client struct {
	httpClient *http.Client
	cache      httpcache.Cacher
	logger     *slog.Logger
}

type config struct {
	httpCache httpcache.Cacher
	logger    *slog.Logger
}

type Option func(*config)

func WithHTTPCache(httpCache httpcache.Cacher) Option {
	return func(c *config) { c.httpCache = httpCache }
}

func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cache:      cfg.httpCache,
		logger:     cfg.logger,
	}, nil
}

func Match(url string) bool {
	url = strings.ToLower(url)
	if !strings.Contains(url, "ringzer0ctf.com") {
		return false
	}
	excludes := []string{"/challenges/", "/forum/"}
	for _, ex := range excludes {
		if strings.Contains(url, ex) {
			return false
		}
	}
	return usernamePattern.MatchString(url)
}

func AuthRequired() bool { return false }

func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	userID, username := extractIdentifiers(urlStr)
	if userID == "" || username == "" {
		return nil, profile.ErrProfileNotFound
	}

	profileURL := fmt.Sprintf("https://ringzer0ctf.com/profile/%s/%s", userID, username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch profile: %w", err)
	}

	htmlContent := string(body)
	if strings.Contains(htmlContent, "not found") || strings.Contains(htmlContent, "404") {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(htmlContent, profileURL, username), nil
}

func extractIdentifiers(url string) (userID, username string) {
	m := usernamePattern.FindStringSubmatch(url)
	if len(m) > 2 {
		userID = m[1]
		username = m[2]
		if idx := strings.Index(username, "?"); idx > 0 {
			username = username[:idx]
		}
		return userID, username
	}
	return "", ""
}

func parseProfile(htmlContent, profileURL, username string) *profile.Profile {
	prof := &profile.Profile{
		Platform:    platform,
		URL:         profileURL,
		Username:    username,
		DisplayName: username,
		Fields:      make(map[string]string),
	}

	namePattern := regexp.MustCompile(`<h[12][^>]*>([^<]+)</h[12]>`)
	if m := namePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" && name != username {
			prof.DisplayName = name
		}
	}

	scorePattern := regexp.MustCompile(`(?i)(?:score|points)[:\s]*(\d+)`)
	if m := scorePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["score"] = m[1]
	}

	rankPattern := regexp.MustCompile(`(?i)rank[:\s#]*(\d+)`)
	if m := rankPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["rank"] = m[1]
	}

	solvedPattern := regexp.MustCompile(`(\d+)\s+challenges?\s+solved`)
	if m := solvedPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["challenges_solved"] = m[1]
	}

	certPattern := regexp.MustCompile(`(?i)certification[:\s]*(\d+)%`)
	if m := certPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["certification_progress"] = m[1] + "%"
	}

	locationPattern := regexp.MustCompile(`(?i)(?:location|country)[:\s]*<?([A-Z][a-zA-Z\s,]+)>?`)
	if m := locationPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		location := strings.TrimSpace(m[1])
		if len(location) > 2 && len(location) < 50 {
			prof.Location = location
		}
	}

	return prof
}
