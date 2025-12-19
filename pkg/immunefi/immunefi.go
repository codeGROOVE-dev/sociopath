package immunefi

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

const platform = "immunefi"

var usernamePattern = regexp.MustCompile(`(?i)immunefi\.com/(?:profile|leaderboard)/([a-zA-Z0-9_-]+)`)

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
	if !strings.Contains(url, "immunefi.com") {
		return false
	}
	// Exclude non-profile URLs
	excludes := []string{"/bounty/", "/bug-bounty/", "/explore/", "/hackers/"}
	for _, ex := range excludes {
		if strings.Contains(url, ex) {
			return false
		}
	}
	return usernamePattern.MatchString(url) || strings.Contains(url, "/leaderboard")
}

func AuthRequired() bool { return false }

func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" && !strings.Contains(urlStr, "leaderboard") {
		return nil, profile.ErrProfileNotFound
	}

	var profileURL string
	if username != "" {
		profileURL = fmt.Sprintf("https://immunefi.com/profile/%s/", username)
	} else {
		profileURL = "https://immunefi.com/leaderboard/"
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

	// Extract display name from title or heading
	namePattern := regexp.MustCompile(`<h1[^>]*>([^<]+)</h1>`)
	if m := namePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" && !strings.Contains(strings.ToLower(name), "leaderboard") {
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

	// Extract vulnerabilities found
	vulnPattern := regexp.MustCompile(`(\d+)\s+vulnerabilit(?:y|ies)\s+found`)
	if m := vulnPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["vulnerabilities_found"] = m[1]
	}

	// Extract bounty earnings
	earningsPattern := regexp.MustCompile(`\$?([\d,]+)\s+(?:earned|in bounties)`)
	if m := earningsPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		earnings := strings.ReplaceAll(m[1], ",", "")
		prof.Fields["earnings"] = earnings
	}

	// Extract rank
	rankPattern := regexp.MustCompile(`#(\d+)\s+(?:on leaderboard|rank)`)
	if m := rankPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["rank"] = m[1]
	}

	// Extract badges/achievements
	badgePattern := regexp.MustCompile(`(?i)(All Star|Hall of Fame|Top (?:10|100)|White Hat)`)
	matches := badgePattern.FindAllStringSubmatch(htmlContent, -1)
	if len(matches) > 0 {
		prof.Badges = make(map[string]string)
		for _, m := range matches {
			if len(m) > 1 {
				badge := strings.TrimSpace(m[1])
				prof.Badges[badge] = "1"
			}
		}
	}

	// Extract social links
	socialPatterns := map[string]*regexp.Regexp{
		"twitter":  regexp.MustCompile(`(?i)twitter\.com/([a-zA-Z0-9_]+)`),
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

	return prof
}
