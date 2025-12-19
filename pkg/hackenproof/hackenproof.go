package hackenproof

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

const platform = "hackenproof"

var usernamePattern = regexp.MustCompile(`(?i)hackenproof\.com/([a-zA-Z0-9_-]+)`)

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
	if !strings.Contains(url, "hackenproof.com") {
		return false
	}
	// Exclude non-profile URLs
	excludes := []string{"/programs/", "/blog/", "/terms", "/pages/"}
	for _, ex := range excludes {
		if strings.Contains(url, ex) {
			return false
		}
	}
	return usernamePattern.MatchString(url)
}

func AuthRequired() bool { return false }

func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, profile.ErrProfileNotFound
	}

	profileURL := fmt.Sprintf("https://hackenproof.com/%s", username)

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
		// Strip query parameters
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

	// Extract display name from meta tags or title
	displayNamePattern := regexp.MustCompile(`<title>([^<]+)(?:\s*[-|]\s*HackenProof)?</title>`)
	if m := displayNamePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" && !strings.Contains(name, "HackenProof") {
			prof.DisplayName = name
		}
	}

	// Extract bio from meta description
	bioPattern := regexp.MustCompile(`<meta\s+(?:name|property)="(?:description|og:description)"\s+content="([^"]+)"`)
	if m := bioPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Bio = strings.TrimSpace(m[1])
	}

	// Extract avatar from og:image
	avatarPattern := regexp.MustCompile(`<meta\s+property="og:image"\s+content="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.AvatarURL = strings.TrimSpace(m[1])
	}

	// Try to extract JSON-LD structured data
	jsonLDPattern := regexp.MustCompile(`<script type="application/ld\+json">([^<]+)</script>`)
	if m := jsonLDPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(m[1]), &data); err == nil {
			if name, ok := data["name"].(string); ok && name != "" {
				prof.DisplayName = name
			}
			if desc, ok := data["description"].(string); ok && desc != "" && prof.Bio == "" {
				prof.Bio = desc
			}
			if img, ok := data["image"].(string); ok && img != "" && prof.AvatarURL == "" {
				prof.AvatarURL = img
			}
		}
	}

	// Extract KYC verification badge
	if strings.Contains(htmlContent, "KYC verified") || strings.Contains(htmlContent, "Verified") {
		prof.Badges = map[string]string{"Verified": "1"}
	}

	// Extract vulnerability counts and stats
	vulnPattern := regexp.MustCompile(`(\d+)\s+(?:vulnerabilities?|bugs?|reports?)`)
	if m := vulnPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["vulnerabilities"] = m[1]
	}

	// Extract rank/reputation
	rankPattern := regexp.MustCompile(`(?i)rank(?:ing)?[:\s]+#?(\d+)`)
	if m := rankPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["rank"] = m[1]
	}

	return prof
}
