// Package googlecal fetches Google Calendar appointment booking page data.
package googlecal

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "googlecal"

// platformInfo implements profile.Platform for Google Calendar.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeScheduling }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Google Calendar appointment URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "calendar.app.google/") ||
		strings.Contains(lower, "calendar.google.com/calendar/appointments/")
}

// AuthRequired returns false because Google Calendar appointment pages are public.
func AuthRequired() bool { return false }

// Client handles Google Calendar requests.
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

// New creates a Google Calendar client.
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
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				// Follow redirects (calendar.app.google -> calendar.google.com)
				return nil
			},
		},
		cache:  cache,
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves a Google Calendar appointment page profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	c.logger.InfoContext(ctx, "fetching googlecal profile", "url", urlStr)

	// Make direct request to follow redirects properly.
	// Note: We don't set a User-Agent here because Google's short URL service
	// (calendar.app.google) returns a JavaScript redirect for browser User-Agents
	// but a proper 302 redirect for simple User-Agents like Go's default.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close

	c.logger.DebugContext(ctx, "response received", "status", resp.StatusCode, "finalURL", resp.Request.URL.String())

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseHTML(body, urlStr), nil
}

func parseHTML(data []byte, urlStr string) *profile.Profile {
	content := string(data)
	// Debug: check content length
	if len(content) < 1000 {
		slog.Debug("short response content", "length", len(content), "content", content)
	} else {
		slog.Debug("response content", "length", len(content), "hasOGTitle", strings.Contains(content, "og:title"))
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Fields:        make(map[string]string),
	}

	// Extract name from og:title - format: "Meet with Thomas - Thomas Strömberg"
	ogTitle := htmlutil.OGTag(content, "og:title")
	if ogTitle != "" {
		p.DisplayName = extractNameFromTitle(ogTitle)
		p.Fields["meeting_title"] = ogTitle
	}

	// Extract avatar from og:image
	ogImage := htmlutil.OGTag(content, "og:image")
	if ogImage != "" {
		p.AvatarURL = ogImage
	}

	// Extract timezone from JavaScript data
	if tz := extractTimezone(content); tz != "" {
		p.Fields["timezone"] = tz
	}

	// Extract schedule ID from URL
	if scheduleID := extractScheduleID(urlStr); scheduleID != "" {
		p.Fields["schedule_id"] = scheduleID
	}

	return p
}

// extractNameFromTitle extracts the person's name from the og:title.
// Format: "Meet with Thomas - Thomas Strömberg" or "Meeting Title - Name".
func extractNameFromTitle(title string) string {
	// Try "X - Name" pattern (name is after the dash)
	if idx := strings.LastIndex(title, " - "); idx != -1 {
		name := strings.TrimSpace(title[idx+3:])
		if name != "" {
			return name
		}
	}

	// Try "Meet with Name" pattern
	if name, found := strings.CutPrefix(title, "Meet with "); found {
		// If there's a dash, take just the first part
		if idx := strings.Index(name, " - "); idx != -1 {
			name = name[:idx]
		}
		return strings.TrimSpace(name)
	}

	return title
}

// extractTimezone extracts the timezone from embedded JavaScript data.
func extractTimezone(content string) string {
	// Look for timezone in JavaScript data - handles both regular and escaped quotes
	// JSON data in JavaScript often has escaped quotes like \"America/New_York\"
	re := regexp.MustCompile(`\\?"(America|Europe|Asia|Africa|Australia|Pacific)/([A-Za-z_]+)\\?"`)
	if m := re.FindStringSubmatch(content); len(m) > 0 {
		return m[1] + "/" + m[2]
	}
	return ""
}

// extractScheduleID extracts the schedule ID from the URL.
func extractScheduleID(urlStr string) string {
	// Pattern: /schedules/SCHEDULE_ID
	re := regexp.MustCompile(`/schedules/([A-Za-z0-9_-]+)`)
	if m := re.FindStringSubmatch(urlStr); len(m) > 1 {
		return m[1]
	}

	// Pattern: calendar.app.google/SCHEDULE_ID
	re2 := regexp.MustCompile(`calendar\.app\.google/([A-Za-z0-9_-]+)`)
	if m := re2.FindStringSubmatch(urlStr); len(m) > 1 {
		return m[1]
	}

	return ""
}
