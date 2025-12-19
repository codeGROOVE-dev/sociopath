// Package xdaforums fetches XDA Forums user profile data.
package xdaforums

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "xdaforums"

// Pre-compiled patterns for parsing XDA Forums HTML.
var (
	profileURLRE   = regexp.MustCompile(`https?://xdaforums\.com/m/([^.]+)\.(\d+)/?`)
	displayNameRE  = regexp.MustCompile(`<h1[^>]*class="[^"]*p-title-value[^"]*"[^>]*>([^<]+)</h1>`)
	userTitleRE    = regexp.MustCompile(`<span[^>]*class="[^"]*userTitle[^"]*"[^>]*>([^<]+)</span>`)
	locationRE     = regexp.MustCompile(`(?i)<dt[^>]*>Location</dt>\s*<dd[^>]*>([^<]+)</dd>`)
	avatarRE       = regexp.MustCompile(`<div[^>]*class="[^"]*avatarScaler[^"]*"[^>]*>.*?<img[^>]+src="([^"]+)"`)
	messagesRE     = regexp.MustCompile(`(?i)<dt[^>]*>Messages</dt>\s*<dd[^>]*>([^<]+)</dd>`)
	reactionScoreRE = regexp.MustCompile(`(?i)<dt[^>]*>Reaction\s+score</dt>\s*<dd[^>]*>([^<]+)</dd>`)
	pointsRE       = regexp.MustCompile(`(?i)<dt[^>]*>Points</dt>\s*<dd[^>]*>([^<]+)</dd>`)
	achievementsRE = regexp.MustCompile(`(?i)<dt[^>]*>Achievements</dt>\s*<dd[^>]*>([^<]+)</dd>`)
	levelRE        = regexp.MustCompile(`(?i)<dt[^>]*>Level</dt>\s*<dd[^>]*>([^<]+)</dd>`)
	joinedRE       = regexp.MustCompile(`(?i)<dt[^>]*>Joined</dt>\s*<dd[^>]*>([^<]+)</dd>`)
)

// platformInfo implements profile.Platform for XDA Forums.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is an XDA Forums user profile URL.
func Match(url string) bool {
	lower := strings.ToLower(url)
	return strings.Contains(lower, "xdaforums.com/m/")
}

// AuthRequired returns false because XDA Forums profiles are public.
func AuthRequired() bool { return false }

// Client handles XDA Forums requests.
type Client struct {
	httpClient *http.Client
	cache      httpcache.Cacher
	logger     *slog.Logger
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache  httpcache.Cacher
	logger *slog.Logger
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache httpcache.Cacher) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates an XDA Forums client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch fetches and parses an XDA Forums user profile.
func (c *Client) Fetch(ctx context.Context, url string) (*profile.Profile, error) {
	// Normalize URL
	url = strings.TrimSpace(url)
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	// Extract username and user ID from URL
	matches := profileURLRE.FindStringSubmatch(url)
	if len(matches) < 3 {
		return nil, fmt.Errorf("invalid XDA Forums profile URL: %s", url)
	}
	username := matches[1]
	userID := matches[2]

	c.logger.InfoContext(ctx, "fetching xda forums profile", "url", url, "username", username, "user_id", userID)

	// Fetch profile page
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, fmt.Errorf("fetching profile: %w", err)
	}

	return parseProfile(string(body), url, username, userID)
}

func parseProfile(html, url, username, userID string) (*profile.Profile, error) {
	p := &profile.Profile{
		URL:      url,
		Platform: platform,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract page title
	p.PageTitle = htmlutil.Title(html)

	// Extract display name
	if matches := displayNameRE.FindStringSubmatch(html); len(matches) > 1 {
		p.DisplayName = htmlutil.DecodeHTMLEntities(strings.TrimSpace(matches[1]))
	}

	// Extract user title/rank
	if matches := userTitleRE.FindStringSubmatch(html); len(matches) > 1 {
		title := htmlutil.DecodeHTMLEntities(strings.TrimSpace(matches[1]))
		if title != "" {
			p.Fields["title"] = title
		}
	}

	// Extract location
	if matches := locationRE.FindStringSubmatch(html); len(matches) > 1 {
		p.Location = htmlutil.DecodeHTMLEntities(strings.TrimSpace(matches[1]))
	}

	// Extract avatar
	if matches := avatarRE.FindStringSubmatch(html); len(matches) > 1 {
		avatarURL := matches[1]
		if !strings.HasPrefix(avatarURL, "http") {
			avatarURL = "https://xdaforums.com" + avatarURL
		}
		p.AvatarURL = avatarURL
	}

	// Extract stats
	if matches := messagesRE.FindStringSubmatch(html); len(matches) > 1 {
		if count, err := parseNumber(matches[1]); err == nil {
			p.Fields["messages"] = strconv.Itoa(count)
		}
	}
	if matches := reactionScoreRE.FindStringSubmatch(html); len(matches) > 1 {
		if count, err := parseNumber(matches[1]); err == nil {
			p.Fields["reaction_score"] = strconv.Itoa(count)
		}
	}
	if matches := pointsRE.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["points"] = htmlutil.DecodeHTMLEntities(strings.TrimSpace(matches[1]))
	}
	if matches := achievementsRE.FindStringSubmatch(html); len(matches) > 1 {
		if count, err := parseNumber(matches[1]); err == nil {
			p.Fields["achievements"] = strconv.Itoa(count)
		}
	}
	if matches := levelRE.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["level"] = htmlutil.DecodeHTMLEntities(strings.TrimSpace(matches[1]))
	}
	if matches := joinedRE.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["joined"] = htmlutil.DecodeHTMLEntities(strings.TrimSpace(matches[1]))
	}

	// Store user ID
	p.Fields["user_id"] = userID

	return p, nil
}

// parseNumber parses a number from a string, handling commas.
func parseNumber(s string) (int, error) {
	s = strings.ReplaceAll(s, ",", "")
	s = strings.TrimSpace(s)
	return strconv.Atoi(s)
}
