package ctf247

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

const platform = "247ctf"

var usernamePattern = regexp.MustCompile(`(?i)247ctf\.com/(?:user|profile)/([a-zA-Z0-9_-]+)`)

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
	if !strings.Contains(url, "247ctf.com") {
		return false
	}
	return usernamePattern.MatchString(url)
}

func AuthRequired() bool { return false }

func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, profile.ErrProfileNotFound
	}

	profileURL := fmt.Sprintf("https://247ctf.com/user/%s", username)

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

func extractUsername(url string) string {
	m := usernamePattern.FindStringSubmatch(url)
	if len(m) > 1 {
		username := m[1]
		if idx := strings.Index(username, "?"); idx > 0 {
			username = username[:idx]
		}
		return username
	}
	return ""
}

func parseProfile(htmlContent, profileURL, username string) *profile.Profile {
	prof := &profile.Profile{
		Platform:    platform,
		URL:         profileURL,
		Username:    username,
		DisplayName: username,
		Fields:      make(map[string]string),
	}

	scorePattern := regexp.MustCompile(`(?i)(?:score|points)[:\s]*(\d+)`)
	if m := scorePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["score"] = m[1]
	}

	solvedPattern := regexp.MustCompile(`(\d+)\s+challenges?\s+(?:solved|completed)`)
	if m := solvedPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["challenges_solved"] = m[1]
	}

	categories := []string{"Web", "Crypto", "Networking", "Reversing", "Pwning"}
	for _, cat := range categories {
		pattern := regexp.MustCompile(fmt.Sprintf(`(?i)%s[^\d]*(\d+)`, regexp.QuoteMeta(cat)))
		if m := pattern.FindStringSubmatch(htmlContent); len(m) > 1 {
			if count := m[1]; count != "0" {
				field := strings.ToLower(cat) + "_solved"
				prof.Fields[field] = count
			}
		}
	}

	return prof
}
