package cryptohack

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

const platform = "cryptohack"

var usernamePattern = regexp.MustCompile(`(?i)cryptohack\.org/user/([a-zA-Z0-9_-]+)`)

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
	if !strings.Contains(url, "cryptohack.org") {
		return false
	}
	// Exclude non-profile URLs
	excludes := []string{"/challenges/", "/blog/", "/faq/"}
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

	profileURL := fmt.Sprintf("https://cryptohack.org/user/%s/", username)

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
	if strings.Contains(htmlContent, "not found") || strings.Contains(htmlContent, "404") ||
		strings.Contains(htmlContent, "User not found") {
		return nil, profile.ErrProfileNotFound
	}

	// Check if we got the homepage instead of a user profile
	// When a user doesn't exist, CryptoHack returns the homepage with HTTP 200
	if strings.Contains(htmlContent, "CryptoHack &ndash; Home") ||
		(strings.Contains(htmlContent, "Weekly Top Users") && strings.Contains(htmlContent, "Learn By Doing")) {
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
		// Remove trailing slash
		username = strings.TrimSuffix(username, "/")
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

	// Extract display name
	namePattern := regexp.MustCompile(`<h1[^>]*>([^<]+)</h1>`)
	if m := namePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" && name != username {
			prof.DisplayName = name
		}
	}

	// Alternative name pattern from title
	titlePattern := regexp.MustCompile(`<title>([^<|]+)\s*(?:\||-)`)
	if m := titlePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" && !strings.Contains(name, "CryptoHack") && prof.DisplayName == username {
			prof.DisplayName = name
		}
	}

	// Extract bio/description
	bioPattern := regexp.MustCompile(`(?i)(?:bio|about)[:\s]*(?:<[^>]+>)*([^<]{10,500})`)
	if m := bioPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		bio := strings.TrimSpace(m[1])
		if bio != "" {
			prof.Bio = bio
		}
	}

	// Extract avatar
	avatarPattern := regexp.MustCompile(`<img[^>]+(?:class="[^"]*avatar[^"]*"|alt="[^"]*avatar[^"]*")[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		avatar := strings.TrimSpace(m[1])
		if !strings.HasPrefix(avatar, "http") {
			avatar = "https://cryptohack.org" + avatar
		}
		prof.AvatarURL = avatar
	}

	// Extract global rank
	rankPattern := regexp.MustCompile(`(?i)(?:global\s+)?rank[:\s#]*(\d+)`)
	if m := rankPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["rank"] = m[1]
	}

	// Extract score/points
	scorePattern := regexp.MustCompile(`(?i)(?:score|points)[:\s]*(\d+)`)
	if m := scorePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["score"] = m[1]
	}

	// Extract level/achievement
	levelPattern := regexp.MustCompile(`(?i)level[:\s]*(\d+|[A-Z][a-z]+)`)
	if m := levelPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["level"] = m[1]
	}

	// Extract challenge categories
	categories := []string{
		"Introduction", "General", "Mathematics", "Symmetric Ciphers",
		"RSA", "Diffie-Hellman", "Elliptic Curves", "Lattices",
		"Post-Quantum", "CTF Archive",
	}

	for _, cat := range categories {
		pattern := regexp.MustCompile(fmt.Sprintf(`(?i)%s[^\d]*(\d+)`, regexp.QuoteMeta(cat)))
		if m := pattern.FindStringSubmatch(htmlContent); len(m) > 1 {
			if count := m[1]; count != "0" {
				field := strings.ToLower(strings.ReplaceAll(cat, " ", "_")) + "_solved"
				prof.Fields[field] = count
			}
		}
	}

	// Extract total challenges solved
	solvedPattern := regexp.MustCompile(`(\d+)\s+challenges?\s+(?:solved|completed)`)
	if m := solvedPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["challenges_solved"] = m[1]
	}

	// Extract location/country
	locationPattern := regexp.MustCompile(`(?i)(?:location|country|from)[:\s]*<?([A-Z][a-zA-Z\s,]+)>?`)
	if m := locationPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		location := strings.TrimSpace(m[1])
		if len(location) > 2 && len(location) < 50 {
			prof.Location = location
		}
	}

	// Extract social links
	socialPatterns := map[string]*regexp.Regexp{
		"twitter": regexp.MustCompile(`(?i)(?:twitter\.com|x\.com)/([a-zA-Z0-9_]+)`),
		"github":  regexp.MustCompile(`(?i)github\.com/([a-zA-Z0-9_-]+)`),
	}

	for socialPlatform, pattern := range socialPatterns {
		if m := pattern.FindStringSubmatch(htmlContent); len(m) > 1 {
			var link string
			switch socialPlatform {
			case "twitter":
				link = fmt.Sprintf("https://twitter.com/%s", m[1])
			case "github":
				link = fmt.Sprintf("https://github.com/%s", m[1])
			}
			prof.SocialLinks = append(prof.SocialLinks, link)
			prof.Fields[socialPlatform] = link
		}
	}

	// Extract Discord username if mentioned
	discordPattern := regexp.MustCompile(`(?i)discord[:\s]*([a-zA-Z0-9_#]+)`)
	if m := discordPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["discord"] = m[1]
	}

	return prof
}
