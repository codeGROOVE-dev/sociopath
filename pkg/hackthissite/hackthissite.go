package hackthissite

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

const platform = "hackthissite"

var usernamePattern = regexp.MustCompile(`(?i)hackthissite\.org/user/view/([a-zA-Z0-9_-]+)`)

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
	if !strings.Contains(url, "hackthissite.org") {
		return false
	}
	// Exclude non-profile URLs
	excludes := []string{"/missions/", "/challenges/", "/forum/", "/irc/"}
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

	profileURL := fmt.Sprintf("https://www.hackthissite.org/user/view/%s", username)

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
	if htmlutil.IsNotFound(htmlContent) {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(htmlContent, profileURL, username)
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

func parseProfile(htmlContent, profileURL, username string) (*profile.Profile, error) {
	prof := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract display name
	namePattern := regexp.MustCompile(`<h1[^>]*>([^<]+)</h1>`)
	if m := namePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" && !htmlutil.IsGenericTitle(name) {
			prof.DisplayName = name
		}
	}

	// If no display name found, it might be a generic page
	if prof.DisplayName == "" {
		// Verify if this is actually a user profile by looking for other indicators
		if !strings.Contains(htmlContent, "Points:") && !strings.Contains(htmlContent, "Rank:") {
			return nil, profile.ErrProfileNotFound
		}
		// Only set DisplayName to username if we found profile markers
		prof.DisplayName = username
	}

	// Extract avatar
	avatarPattern := regexp.MustCompile(`<img[^>]+(?:class="[^"]*avatar[^"]*"|alt="[^"]*avatar[^"]*")[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		avatar := strings.TrimSpace(m[1])
		if !strings.HasPrefix(avatar, "http") {
			avatar = "https://www.hackthissite.org" + avatar
		}
		prof.AvatarURL = avatar
	}

	// Extract rank
	rankPattern := regexp.MustCompile(`(?i)(?:rank|level)[:\s#]*(\d+)`)
	if m := rankPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["rank"] = m[1]
	}

	// Extract points/score
	pointsPattern := regexp.MustCompile(`(?i)(?:points?|score)[:\s]*(\d+)`)
	if m := pointsPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["points"] = m[1]
	}

	// Extract missions completed
	missionsPattern := regexp.MustCompile(`(\d+)\s+missions?\s+(?:completed|solved)`)
	if m := missionsPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["missions_completed"] = m[1]
	}

	// Extract challenges completed
	challengesPattern := regexp.MustCompile(`(\d+)\s+challenges?\s+(?:completed|solved)`)
	if m := challengesPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["challenges_completed"] = m[1]
	}

	// Extract member since/join date
	joinPattern := regexp.MustCompile(`(?i)(?:member since|joined)[:\s]*([A-Z][a-z]+\s+\d{1,2},?\s+\d{4})`)
	if m := joinPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["joined"] = m[1]
	}

	// Extract location
	locationPattern := regexp.MustCompile(`(?i)(?:location|country)[:\s]*<?([A-Z][a-zA-Z\s,]+)>?`)
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

	// Extract mission types completed
	missionTypes := []string{"Basic", "Realistic", "Application", "Programming", "Phonephreaking", "Forensic", "Extbasic", "Stego"}
	for _, mType := range missionTypes {
		pattern := regexp.MustCompile(fmt.Sprintf(`(?i)%s[^\d]*(\d+)`, regexp.QuoteMeta(mType)))
		if m := pattern.FindStringSubmatch(htmlContent); len(m) > 1 {
			if count := m[1]; count != "0" {
				field := strings.ToLower(mType) + "_missions"
				prof.Fields[field] = count
			}
		}
	}

	return prof, nil
}
