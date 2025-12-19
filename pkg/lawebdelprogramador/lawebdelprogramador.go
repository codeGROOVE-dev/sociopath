// Package lawebdelprogramador fetches La Web del Programador user profile data.
package lawebdelprogramador

import (
	"context"
	"crypto/tls"
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

const platform = "lawebdelprogramador"

// platformInfo implements profile.Platform for La Web del Programador.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a La Web del Programador profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "lawebdelprogramador.com/programadores/") ||
		strings.Contains(lower, "lawebdelprogramador.com/perfil/") ||
		strings.Contains(lower, "lawebdelprogramador.com/usuario/")
}

// AuthRequired returns false for now (will update if auth is required).
func AuthRequired() bool { return false }

// Client handles La Web del Programador requests.
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

// New creates a La Web del Programador client.
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

// Fetch retrieves a La Web del Programador profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching lawebdelprogramador profile", "url", urlStr, "username", username)

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
	if strings.Contains(content, "no existe") || strings.Contains(content, "not found") {
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
	namePattern := regexp.MustCompile(`<h1[^>]*>(?:Perfil de\s+)?([^<]+)</h1>`)
	if m := namePattern.FindStringSubmatch(content); len(m) > 1 {
		p.DisplayName = strings.TrimSpace(m[1])
	}

	// Try alternative name pattern
	if p.DisplayName == "" {
		namePattern2 := regexp.MustCompile(`<title>([^-|<]+)(?:\s*-|\s*\|)`)
		if m := namePattern2.FindStringSubmatch(content); len(m) > 1 {
			name := strings.TrimSpace(m[1])
			if !strings.Contains(strings.ToLower(name), "la web del programador") {
				p.DisplayName = name
			}
		}
	}

	// Extract member since date
	datePattern := regexp.MustCompile(`(?i)(?:miembro desde|registrado)[^>]*>\s*([^<]+)</`)
	if m := datePattern.FindStringSubmatch(content); len(m) > 1 {
		p.CreatedAt = strings.TrimSpace(m[1])
	}

	// Extract avatar
	avatarPattern := regexp.MustCompile(`<img[^>]+(?:class="[^"]*avatar[^"]*"|alt="[^"]*avatar[^"]*")[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(content); len(m) > 1 {
		p.AvatarURL = m[1]
		if !strings.HasPrefix(p.AvatarURL, "http") {
			p.AvatarURL = "https://www.lawebdelprogramador.com" + p.AvatarURL
		}
	}

	// Extract statistics
	if m := regexp.MustCompile(`(?i)(\d+)\s+(?:mensajes|posts)`).FindStringSubmatch(content); len(m) > 1 {
		p.Fields["posts"] = m[1]
	}
	if m := regexp.MustCompile(`(?i)(\d+)\s+(?:respuestas|replies)`).FindStringSubmatch(content); len(m) > 1 {
		p.Fields["replies"] = m[1]
	}
	if m := regexp.MustCompile(`(?i)(\d+)\s+(?:puntos|points)`).FindStringSubmatch(content); len(m) > 1 {
		p.Fields["points"] = m[1]
	}

	// Extract location
	locPattern := regexp.MustCompile(`(?i)(?:ubicaci[oó]n|location|pa[ií]s)[^>]*>\s*([^<]+)</`)
	if m := locPattern.FindStringSubmatch(content); len(m) > 1 {
		loc := strings.TrimSpace(htmlutil.StripHTML(m[1]))
		if loc != "" && loc != "No especificado" {
			p.Location = loc
		}
	}

	// Extract bio/about
	bioPattern := regexp.MustCompile(`(?s)(?i)<div[^>]+class="[^"]*(?:bio|about|descripcion)[^"]*"[^>]*>(.+?)</div>`)
	if m := bioPattern.FindStringSubmatch(content); len(m) > 1 {
		bio := htmlutil.StripHTML(m[1])
		bio = strings.TrimSpace(bio)
		if bio != "" {
			p.Bio = bio
		}
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract website
	websitePattern := regexp.MustCompile(`(?i)(?:sitio web|website|web)[^>]*href="([^"]+)"`)
	if m := websitePattern.FindStringSubmatch(content); len(m) > 1 {
		website := strings.TrimSpace(m[1])
		if website != "" && !strings.Contains(website, "lawebdelprogramador.com") {
			p.Website = website
		}
	}

	return p, nil
}

func extractUsername(urlStr string) string {
	// Try various URL patterns
	patterns := []string{
		"/programadores/",
		"/perfil/",
		"/usuario/",
		"/user/",
	}

	for _, pattern := range patterns {
		if idx := strings.Index(urlStr, pattern); idx != -1 {
			username := urlStr[idx+len(pattern):]
			username = strings.Split(username, "/")[0]
			username = strings.Split(username, "?")[0]
			return strings.TrimSpace(username)
		}
	}

	return ""
}
