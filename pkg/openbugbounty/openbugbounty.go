package openbugbounty

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

const platform = "openbugbounty"

var usernamePattern = regexp.MustCompile(`(?i)openbugbounty\.org/researchers/([a-zA-Z0-9_-]+)`)

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
	if !strings.Contains(url, "openbugbounty.org") {
		return false
	}
	// Exclude non-profile URLs
	excludes := []string{"/reports/", "/submissions/", "/faq/", "/blog/"}
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

	profileURL := fmt.Sprintf("https://www.openbugbounty.org/researchers/%s/", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

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
		// Remove trailing slashes or additional path components
		if idx := strings.Index(username, "/"); idx > 0 {
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

	// Extract real name
	namePattern := regexp.MustCompile(`(?i)(?:real name|name)[:\s]*<[^>]+>([^<]+)</`)
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
		if name != "" && !strings.Contains(name, "Open Bug Bounty") && prof.DisplayName == username {
			prof.DisplayName = name
		}
	}

	// Extract bio/about me
	bioPattern := regexp.MustCompile(`(?i)(?:about me|bio)[:\s]*(?:<[^>]+>)*([^<]{10,500})`)
	if m := bioPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		bio := strings.TrimSpace(m[1])
		if bio != "" {
			prof.Bio = bio
		}
	}

	// Extract reputation
	repPattern := regexp.MustCompile(`(?i)reputation[:\s]+(\d+)`)
	if m := repPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["reputation"] = m[1]
	}

	// Extract vulnerability count
	vulnPattern := regexp.MustCompile(`(?i)(?:helped fix|fixed vulnerabilities)[:\s]*(\d+)`)
	if m := vulnPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["vulnerabilities_fixed"] = m[1]
	}

	// Alternative vulnerability pattern
	fixedPattern := regexp.MustCompile(`(\d+)\s+vulnerabilit(?:y|ies)`)
	if m := fixedPattern.FindStringSubmatch(htmlContent); len(m) > 1 && prof.Fields["vulnerabilities_fixed"] == "" {
		prof.Fields["vulnerabilities_fixed"] = m[1]
	}

	// Extract email (obfuscated handling)
	emailPattern := regexp.MustCompile(`(?i)(?:email|contact)[:\s]*<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?`)
	if m := emailPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		// Email found - could be added to Fields map if needed
		prof.Fields["email"] = m[1]
	}

	// Extract certifications
	certPattern := regexp.MustCompile(`(?i)(?:certification|cert)[s]?[:\s]*([^<\n]{5,100})`)
	if m := certPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		certs := strings.TrimSpace(m[1])
		if certs != "" {
			prof.Fields["certifications"] = certs
		}
	}

	// Extract specific certification badges (OSCP, CEH, etc.)
	certBadges := []string{"OSCP", "CEH", "CPTE", "eCPPT", "eWPT", "CSIL", "CISSP"}
	for _, cert := range certBadges {
		if strings.Contains(htmlContent, cert) {
			if prof.Badges == nil {
				prof.Badges = make(map[string]string)
			}
			prof.Badges[cert] = "1"
		}
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

	// Extract Hall of Fame mentions
	hofPattern := regexp.MustCompile(`(?i)hall of fame`)
	if hofPattern.MatchString(htmlContent) {
		if prof.Badges == nil {
			prof.Badges = make(map[string]string)
		}
		prof.Badges["Hall of Fame"] = "1"
	}

	// Extract location/country
	locationPattern := regexp.MustCompile(`(?i)(?:location|country|from)[:\s]*<?([A-Z][a-zA-Z\s]+)>?`)
	if m := locationPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		location := strings.TrimSpace(m[1])
		if len(location) > 2 && len(location) < 50 {
			prof.Location = location
		}
	}

	return prof
}
