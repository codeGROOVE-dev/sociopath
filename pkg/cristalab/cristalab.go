// Package cristalab fetches Cristalab user profile data.
package cristalab

import (
	"context"
	"crypto/tls"
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

const platform = "cristalab"

// platformInfo implements profile.Platform for Cristalab.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Cristalab profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "cristalab.com/usuario/")
}

// AuthRequired returns false because Cristalab profiles are public.
func AuthRequired() bool { return false }

// Client handles Cristalab requests.
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

// New creates a Cristalab client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves a Cristalab profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching cristalab profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; sociopath/1.0)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "es,en;q=0.9")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(urlStr, username, body)
}

func parseProfile(urlStr, username string, data []byte) (*profile.Profile, error) {
	content := string(data)

	// Check if profile exists
	if strings.Contains(content, "El usuario no existe") || strings.Contains(content, "not found") {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Extract display name from title or header
	// Pattern: "usuario es Usuario de Cristalab"
	namePattern := regexp.MustCompile(`<title>([^<]+)\s+es\s+Usuario\s+de\s+Cristalab`)
	if m := namePattern.FindStringSubmatch(content); len(m) > 1 {
		p.DisplayName = strings.TrimSpace(m[1])
	}

	// Extract member since date
	// Pattern: "Desde el 28 Nov 2011" or "Desde el 01 Jun 2007"
	datePattern := regexp.MustCompile(`Desde el\s+(\d{2}\s+\w{3}\s+\d{4})`)
	if m := datePattern.FindStringSubmatch(content); len(m) > 1 {
		if t, err := parseSpanishDate(m[1]); err == nil {
			p.CreatedAt = t.Format(time.RFC3339)
		}
	}

	// Extract clabLevel (reputation)
	levelPattern := regexp.MustCompile(`(\d+)\s+de\s+clabLevel`)
	if m := levelPattern.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["clabLevel"] = m[1]
	}

	// Extract statistics
	// Messages, tutorials, articles, examples
	if m := regexp.MustCompile(`(\d+)\s+mensajes?`).FindStringSubmatch(content); len(m) > 1 {
		if count, _ := strconv.Atoi(m[1]); count > 0 {
			p.Fields["messages"] = m[1]
		}
	}
	if m := regexp.MustCompile(`(\d+)\s+tutoriales?`).FindStringSubmatch(content); len(m) > 1 {
		if count, _ := strconv.Atoi(m[1]); count > 0 {
			p.Fields["tutorials"] = m[1]
		}
	}
	if m := regexp.MustCompile(`(\d+)\s+art[ií]culos?`).FindStringSubmatch(content); len(m) > 1 {
		if count, _ := strconv.Atoi(m[1]); count > 0 {
			p.Fields["articles"] = m[1]
		}
	}
	if m := regexp.MustCompile(`(\d+)\s+ejemplos?`).FindStringSubmatch(content); len(m) > 1 {
		if count, _ := strconv.Atoi(m[1]); count > 0 {
			p.Fields["examples"] = m[1]
		}
	}

	// Extract avatar
	avatarPattern := regexp.MustCompile(`<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(content); len(m) > 1 {
		p.AvatarURL = m[1]
		if !strings.HasPrefix(p.AvatarURL, "http") {
			p.AvatarURL = "https://www.cristalab.com" + p.AvatarURL
		}
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract bio/about if present
	bioPattern := regexp.MustCompile(`(?s)<div[^>]+class="[^"]*bio[^"]*"[^>]*>(.+?)</div>`)
	if m := bioPattern.FindStringSubmatch(content); len(m) > 1 {
		bio := htmlutil.StripHTML(m[1])
		bio = strings.TrimSpace(bio)
		if bio != "" && bio != "desconocido" {
			p.Bio = bio
		}
	}

	// Extract location if present
	locPattern := regexp.MustCompile(`(?i)<[^>]+>(?:ubicaci[oó]n|location)[^<]*</[^>]+>\s*<[^>]+>([^<]+)</`)
	if m := locPattern.FindStringSubmatch(content); len(m) > 1 {
		loc := strings.TrimSpace(htmlutil.StripHTML(m[1]))
		if loc != "" && loc != "desconocido" && loc != "unknown" {
			p.Location = loc
		}
	}

	return p, nil
}

func extractUsername(urlStr string) string {
	// URL format: cristalab.com/usuario/123637-mikiperu
	// Extract: mikiperu
	if idx := strings.Index(urlStr, "/usuario/"); idx != -1 {
		username := urlStr[idx+len("/usuario/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		// Remove ID prefix: "123637-mikiperu" -> "mikiperu"
		if parts := strings.SplitN(username, "-", 2); len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
		return strings.TrimSpace(username)
	}
	return ""
}

// parseSpanishDate parses Spanish date format like "28 Nov 2011".
func parseSpanishDate(dateStr string) (time.Time, error) {
	monthMap := map[string]string{
		"Ene": "Jan", "Feb": "Feb", "Mar": "Mar", "Abr": "Apr",
		"May": "May", "Jun": "Jun", "Jul": "Jul", "Ago": "Aug",
		"Sep": "Sep", "Oct": "Oct", "Nov": "Nov", "Dic": "Dec",
	}

	parts := strings.Fields(dateStr)
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("invalid date format: %s", dateStr)
	}

	month, ok := monthMap[parts[1]]
	if !ok {
		return time.Time{}, fmt.Errorf("unknown month: %s", parts[1])
	}

	englishDate := fmt.Sprintf("%s %s %s", parts[0], month, parts[2])
	return time.Parse("02 Jan 2006", englishDate)
}
