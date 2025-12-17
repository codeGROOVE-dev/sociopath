// Package tradingview fetches TradingView user profile data.
package tradingview

import (
	"context"
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

const platform = "tradingview"

// platformInfo implements profile.Platform for TradingView.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)tradingview\.com/u/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a TradingView profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "tradingview.com/u/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because TradingView profiles are public.
func AuthRequired() bool { return false }

// Client handles TradingView requests.
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

// New creates a TradingView client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	cache := cfg.cache
	if cache == nil {
		cache = httpcache.NewNull()
	}

	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a TradingView profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)

	c.logger.InfoContext(ctx, "fetching tradingview profile", "url", urlStr, "username", username)

	profileURL := "https://www.tradingview.com/u/" + username + "/"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpcache.UserAgent)

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(body, profileURL, username), nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	prof := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		DisplayName:   username,
		Fields:        make(map[string]string),
	}

	// Extract username from JSON - "username":"austenbryan"
	userJSONPattern := regexp.MustCompile(`"username":"([^"]+)"`)
	if m := userJSONPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Username = m[1]
		if prof.DisplayName == "" || prof.DisplayName == username {
			prof.DisplayName = m[1]
		}
	}

	// Extract followers count
	followersPattern := regexp.MustCompile(`"followers":(\d+)`)
	if m := followersPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["followers"] = m[1]
	}

	// Extract following count
	followingPattern := regexp.MustCompile(`"following":(\d+)`)
	if m := followingPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["following"] = m[1]
	}

	// Extract ideas/charts count
	chartsPattern := regexp.MustCompile(`"charts_total":(\d+)`)
	if m := chartsPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["charts"] = m[1]
	}

	// Extract scripts count
	scriptsPattern := regexp.MustCompile(`"scripts_total":(\d+)`)
	if m := scriptsPattern.FindStringSubmatch(content); len(m) > 1 {
		prof.Fields["scripts"] = m[1]
	}

	// Extract date joined (Unix timestamp)
	joinedPattern := regexp.MustCompile(`"date_joined":(\d+(?:\.\d+)?)`)
	if m := joinedPattern.FindStringSubmatch(content); len(m) > 1 {
		if ts, err := strconv.ParseFloat(m[1], 64); err == nil {
			t := time.Unix(int64(ts), 0)
			prof.CreatedAt = t.Format("2006-01-02")
		}
	}

	// Extract last login (Unix timestamp)
	lastLoginPattern := regexp.MustCompile(`"last_login":(\d+(?:\.\d+)?)`)
	if m := lastLoginPattern.FindStringSubmatch(content); len(m) > 1 {
		if ts, err := strconv.ParseFloat(m[1], 64); err == nil {
			t := time.Unix(int64(ts), 0)
			prof.Fields["last_login"] = t.Format("2006-01-02")
		}
	}

	// Extract bio/signature
	bioPattern := regexp.MustCompile(`"signature":"([^"]*)"`)
	if m := bioPattern.FindStringSubmatch(content); len(m) > 1 && m[1] != "" {
		prof.Bio = m[1]
	}

	// Extract social links from JSON
	socialPatterns := map[string]*regexp.Regexp{
		"twitter":   regexp.MustCompile(`"twitter_username":"([^"]+)"`),
		"website":   regexp.MustCompile(`"website_url":"([^"]+)"`),
		"instagram": regexp.MustCompile(`"instagram_username":"([^"]+)"`),
		"youtube":   regexp.MustCompile(`"youtube_channel":"([^"]+)"`),
	}

	for key, pattern := range socialPatterns {
		if m := pattern.FindStringSubmatch(content); len(m) > 1 && m[1] != "" {
			var link string
			switch key {
			case "twitter":
				link = "https://twitter.com/" + m[1]
			case "instagram":
				link = "https://instagram.com/" + m[1]
			case "youtube":
				link = "https://youtube.com/" + m[1]
			case "website":
				link = m[1]
				prof.Website = link
			default:
				// Unknown social platform
			}
			if link != "" {
				prof.SocialLinks = append(prof.SocialLinks, link)
			}
		}
	}

	// Try og:title for display name
	ogTitle := htmlutil.OGTag(content, "og:title")
	if ogTitle != "" && !strings.Contains(strings.ToLower(ogTitle), "tradingview") {
		prof.DisplayName = strings.TrimSpace(ogTitle)
	}

	// Try og:image for avatar
	ogImage := htmlutil.OGTag(content, "og:image")
	if ogImage != "" && !strings.Contains(ogImage, "logo") {
		prof.AvatarURL = ogImage
	}

	return prof
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
