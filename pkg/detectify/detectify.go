package detectify

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

const platform = "detectify"

var (
	leaderboardPattern = regexp.MustCompile(`(?i)detectify\.com/crowdsource/leaderboard`)
	usernamePattern    = regexp.MustCompile(`(?i)detectify\.com/(?:crowdsource/)?(?:user|researcher|profile)/([a-zA-Z0-9_-]+)`)
)

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
	if !strings.Contains(url, "detectify.com") {
		return false
	}
	// Match leaderboard or potential profile URLs
	return leaderboardPattern.MatchString(url) || usernamePattern.MatchString(url)
}

func AuthRequired() bool { return false }

func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)

	var profileURL string
	if username != "" {
		// Try to fetch researcher profile if username was extracted
		profileURL = fmt.Sprintf("https://detectify.com/crowdsource/researcher/%s", username)
	} else {
		// Default to leaderboard
		profileURL = "https://detectify.com/crowdsource/leaderboard"
	}

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

	displayName := username
	if username == "" {
		displayName = "leaderboard"
	}

	return parseProfile(htmlContent, profileURL, displayName), nil
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

	// Extract researcher name from heading or title
	namePattern := regexp.MustCompile(`<h[12][^>]*>([^<]+(?:researcher|hacker)?[^<]*)</h[12]>`)
	if m := namePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" && !strings.Contains(strings.ToLower(name), "leaderboard") && !strings.Contains(strings.ToLower(name), "detectify") {
			prof.DisplayName = name
		}
	}

	// Extract from meta tags
	metaNamePattern := regexp.MustCompile(`<meta\s+(?:name|property)="(?:og:title|title)"\s+content="([^"]+)"`)
	if m := metaNamePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if prof.DisplayName == username && name != "" && !strings.Contains(strings.ToLower(name), "detectify") {
			prof.DisplayName = name
		}
	}

	// Extract bio/description
	bioPattern := regexp.MustCompile(`<meta\s+(?:name|property)="description"\s+content="([^"]+)"`)
	if m := bioPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Bio = strings.TrimSpace(m[1])
	}

	// Extract avatar
	avatarPattern := regexp.MustCompile(`<meta\s+property="og:image"\s+content="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.AvatarURL = strings.TrimSpace(m[1])
	}

	// Extract rank from leaderboard
	rankPattern := regexp.MustCompile(`(?i)(?:#|rank\s+)(\d+)`)
	if m := rankPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["rank"] = m[1]
	}

	// Extract points by severity
	severityPatterns := map[string]string{
		"critical_points": `(?i)critical[^\d]*(\d+)\s*(?:points?|pts?)`,
		"high_points":     `(?i)high[^\d]*(\d+)\s*(?:points?|pts?)`,
		"medium_points":   `(?i)medium[^\d]*(\d+)\s*(?:points?|pts?)`,
		"low_points":      `(?i)low[^\d]*(\d+)\s*(?:points?|pts?)`,
	}

	for field, patternStr := range severityPatterns {
		pattern := regexp.MustCompile(patternStr)
		if m := pattern.FindStringSubmatch(htmlContent); len(m) > 1 {
			prof.Fields[field] = m[1]
		}
	}

	// Extract total points
	totalPattern := regexp.MustCompile(`(?i)(?:total|score)[:\s]+(\d+)\s*(?:points?|pts?)`)
	if m := totalPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["total_points"] = m[1]
	}

	// Extract modules/vulnerabilities found
	modulesPattern := regexp.MustCompile(`(\d+)\s+(?:modules?|vulnerabilities?|findings?)`)
	if m := modulesPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["modules"] = m[1]
	}

	// Extract period information (Q4 2025, All-time, etc.)
	periodPattern := regexp.MustCompile(`(?i)(Q[1-4]\s+\d{4}|all[- ]time|year\s+\d{4})`)
	if m := periodPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["period"] = strings.TrimSpace(m[1])
	}

	// Extract social links
	socialPatterns := map[string]*regexp.Regexp{
		"twitter":  regexp.MustCompile(`(?i)(?:twitter\.com|x\.com)/([a-zA-Z0-9_]+)`),
		"github":   regexp.MustCompile(`(?i)github\.com/([a-zA-Z0-9_-]+)`),
		"linkedin": regexp.MustCompile(`(?i)linkedin\.com/in/([a-zA-Z0-9_-]+)`),
	}

	for socialPlatform, pattern := range socialPatterns {
		if m := pattern.FindStringSubmatch(htmlContent); len(m) > 1 {
			var link string
			switch socialPlatform {
			case "twitter":
				link = fmt.Sprintf("https://twitter.com/%s", m[1])
			case "github":
				link = fmt.Sprintf("https://github.com/%s", m[1])
			case "linkedin":
				link = fmt.Sprintf("https://linkedin.com/in/%s", m[1])
			}
			prof.SocialLinks = append(prof.SocialLinks, link)
			prof.Fields[socialPlatform] = link
		}
	}

	// Top 3 badge detection
	if strings.Contains(htmlContent, "1st place") || strings.Contains(htmlContent, "#1") {
		prof.Badges = map[string]string{"1st Place": "1"}
	} else if strings.Contains(htmlContent, "2nd place") || strings.Contains(htmlContent, "#2") {
		prof.Badges = map[string]string{"2nd Place": "1"}
	} else if strings.Contains(htmlContent, "3rd place") || strings.Contains(htmlContent, "#3") {
		prof.Badges = map[string]string{"3rd Place": "1"}
	}

	return prof
}
