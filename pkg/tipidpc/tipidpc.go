// Package tipidpc fetches TipidPC user profile data.
package tipidpc

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "tipidpc"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)tipidpc\.com/(?:useritems|ratings)\.php\?username=([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a TipidPC user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "tipidpc.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because TipidPC profiles are public.
func AuthRequired() bool { return false }

// Client handles TipidPC requests.
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

// New creates a TipidPC client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

var (
	memberStatusPattern   = regexp.MustCompile(`(?i)<b>([^<]+Member[^<]*)</b>`)
	memberSincePattern    = regexp.MustCompile(`(?i)Member since:\s*([^<]+)</span>`)
	lastOnlinePattern     = regexp.MustCompile(`(?i)Last online:\s*([^<]+)</span>`)
	locationPattern       = regexp.MustCompile(`(?i)Location:\s*</b>\s*([^<]+)</span>`)
	contactPattern        = regexp.MustCompile(`(?i)Contact:\s*</b>\s*([0-9]+)</span>`)
	feedbackPositivePattern = regexp.MustCompile(`(?i)(\d+)%\s*-\s*(\d+)\s+POSITIVE`)
	feedbackNegativePattern = regexp.MustCompile(`(?i)(\d+)%\s*-\s*(\d+)\s+NEGATIVE`)
)

// Fetch retrieves a TipidPC user profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching tipidpc profile", "url", urlStr, "username", username)

	// Fetch the useritems page first
	profileURL := "https://tipidpc.com/useritems.php?username=" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("DNT", "1")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	content := string(body)

	// Check if profile exists
	if strings.Contains(content, "not found") || strings.Contains(content, "does not exist") {
		return nil, profile.ErrProfileNotFound
	}

	// Also fetch ratings page for additional info
	ratingsURL := "https://tipidpc.com/ratings.php?username=" + username
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, ratingsURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req2.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req2.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

	ratingsBody, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req2, c.logger)
	if err == nil {
		// Append ratings content for parsing
		content += "\n" + string(ratingsBody)
	}

	return parseProfile(content, username, urlStr), nil
}

func parseProfile(htmlContent, username, url string) *profile.Profile {
	p := &profile.Profile{
		Platform:    platform,
		URL:         url,
		Username:    username,
		DisplayName: username,
		Fields:      make(map[string]string),
	}

	// Extract member status
	if m := memberStatusPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		status := strings.TrimSpace(html.UnescapeString(m[1]))
		if status != "" {
			p.Fields["member_status"] = status
		}
	}

	// Extract member since date
	if m := memberSincePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		since := strings.TrimSpace(html.UnescapeString(m[1]))
		if since != "" {
			p.Fields["member_since"] = since
		}
	}

	// Extract last online
	if m := lastOnlinePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		lastOnline := strings.TrimSpace(html.UnescapeString(m[1]))
		if lastOnline != "" {
			p.Fields["last_online"] = lastOnline
		}
	}

	// Extract location
	if m := locationPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		loc := strings.TrimSpace(html.UnescapeString(m[1]))
		if loc != "" {
			p.Location = loc
		}
	}

	// Extract contact (phone number)
	if m := contactPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		contact := strings.TrimSpace(m[1])
		if contact != "" {
			p.Fields["contact"] = contact
		}
	}

	// Extract positive feedback
	if m := feedbackPositivePattern.FindStringSubmatch(htmlContent); len(m) > 2 {
		percentage := m[1]
		count := m[2]
		p.Fields["positive_feedback_percentage"] = percentage + "%"
		p.Fields["positive_feedback_count"] = count
	}

	// Extract negative feedback
	if m := feedbackNegativePattern.FindStringSubmatch(htmlContent); len(m) > 2 {
		percentage := m[1]
		count := m[2]
		p.Fields["negative_feedback_percentage"] = percentage + "%"
		p.Fields["negative_feedback_count"] = count
	}

	// Extract social media links if any
	socialLinks := htmlutil.SocialLinks(htmlContent)
	if len(socialLinks) > 0 {
		p.SocialLinks = socialLinks
	}

	return p
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
