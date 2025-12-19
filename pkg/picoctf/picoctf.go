package picoctf

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

const platform = "picoctf"

var (
	usernamePattern     = regexp.MustCompile(`(?i)(?:play\.)?picoctf\.org/users/([a-zA-Z0-9_-]+)`)
	participantPattern  = regexp.MustCompile(`(?i)(?:play\.)?picoctf\.org/participants/(\d+)`)
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
	if !strings.Contains(url, "picoctf.org") {
		return false
	}
	// Exclude non-profile URLs
	excludes := []string{"/challenges", "/scoreboard", "/help", "/practice"}
	for _, ex := range excludes {
		if strings.Contains(url, ex) {
			return false
		}
	}
	return usernamePattern.MatchString(url) || participantPattern.MatchString(url)
}

func AuthRequired() bool { return false }

func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username, participantID := extractIdentifiers(urlStr)

	var profileURL string
	if username != "" {
		profileURL = fmt.Sprintf("https://play.picoctf.org/users/%s", username)
	} else if participantID != "" {
		profileURL = fmt.Sprintf("https://play.picoctf.org/participants/%s", participantID)
	} else {
		return nil, profile.ErrProfileNotFound
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
	if htmlutil.IsNotFound(htmlContent) || strings.Contains(htmlContent, "Private User") {
		return nil, profile.ErrProfileNotFound
	}

	displayName := username
	if username == "" {
		displayName = fmt.Sprintf("participant_%s", participantID)
	}

	return parseProfile(htmlContent, profileURL, displayName)
}

func extractIdentifiers(url string) (username, participantID string) {
	if m := usernamePattern.FindStringSubmatch(url); len(m) > 1 {
		username = m[1]
		if idx := strings.Index(username, "?"); idx > 0 {
			username = username[:idx]
		}
		return username, ""
	}

	if m := participantPattern.FindStringSubmatch(url); len(m) > 1 {
		participantID = m[1]
		if idx := strings.Index(participantID, "?"); idx > 0 {
			participantID = participantID[:idx]
		}
		return "", participantID
	}

	return "", ""
}

func parseProfile(htmlContent, profileURL, username string) (*profile.Profile, error) {
	prof := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract join date
	joinPattern := regexp.MustCompile(`Player since\s+([A-Z][a-z]+\s+\d{4})`)
	if m := joinPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["joined"] = m[1]
	}

	// If no join date found, it might be a generic page
	if prof.Fields["joined"] == "" && !strings.Contains(htmlContent, "score") && !strings.Contains(htmlContent, "rank") {
		return nil, profile.ErrProfileNotFound
	}

	prof.DisplayName = username

	// Extract scores by difficulty
	scorePatterns := map[string]*regexp.Regexp{
		"easy_solved":      regexp.MustCompile(`Easy[^\d]*(\d+)`),
		"medium_solved":    regexp.MustCompile(`Medium[^\d]*(\d+)`),
		"hard_solved":      regexp.MustCompile(`Hard[^\d]*(\d+)`),
		"very_hard_solved": regexp.MustCompile(`Very Hard[^\d]*(\d+)`),
	}

	for field, pattern := range scorePatterns {
		if m := pattern.FindStringSubmatch(htmlContent); len(m) > 1 {
			if count := m[1]; count != "0" {
				prof.Fields[field] = count
			}
		}
	}

	// Extract category progress
	categories := []string{"Binary Exploitation", "Cryptography", "Forensics", "General Skills", "Reverse Engineering", "Web Exploitation"}
	for _, cat := range categories {
		pattern := regexp.MustCompile(fmt.Sprintf(`%s[^\d]*(\d+)`, regexp.QuoteMeta(cat)))
		if m := pattern.FindStringSubmatch(htmlContent); len(m) > 1 {
			if count := m[1]; count != "0" {
				field := strings.ToLower(strings.ReplaceAll(cat, " ", "_"))
				prof.Fields[field] = count
			}
		}
	}

	// Extract total score/points
	scorePattern := regexp.MustCompile(`(?i)(?:score|points)[:\s]+(\d+)`)
	if m := scorePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["score"] = m[1]
	}

	// Extract rank
	rankPattern := regexp.MustCompile(`(?i)rank[:\s]+#?(\d+)`)
	if m := rankPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		prof.Fields["rank"] = m[1]
	}

	// Extract team name
	teamPattern := regexp.MustCompile(`(?i)team[:\s]+([^\<\n]+)`)
			if m := teamPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
			team := strings.TrimSpace(m[1])
			if team != "" && team != "None" {
				prof.Groups = append(prof.Groups, team)
				prof.Fields["team"] = team
			}
		}
	
		return prof, nil
	}
