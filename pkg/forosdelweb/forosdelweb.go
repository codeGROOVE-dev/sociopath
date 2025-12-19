// Package forosdelweb fetches Foros del Web user profile data.
// Note: This platform requires authentication to view full profiles.
package forosdelweb

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

const platform = "forosdelweb"

// platformInfo implements profile.Platform for Foros del Web.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Foros del Web profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "forosdelweb.com/miembros/") ||
		strings.Contains(lower, "forosdelweb.com/members/")
}

// AuthRequired returns true because Foros del Web requires authentication to view profiles.
func AuthRequired() bool { return true }

// Client handles Foros del Web requests.
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

// New creates a Foros del Web client.
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

// Fetch retrieves a Foros del Web profile.
// Note: This will likely fail without authentication cookies.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching forosdelweb profile", "url", urlStr, "username", username)

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

	// Check for authentication requirement
	if strings.Contains(content, "no cuentas con las credenciales correctas") ||
		strings.Contains(content, "not authorized") ||
		strings.Contains(content, "debe iniciar sesión") {
		return nil, fmt.Errorf("authentication required to view profile")
	}

	// Check if profile exists
	if strings.Contains(content, "perfil no existe") || strings.Contains(content, "not found") {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Extract display name
	namePattern := regexp.MustCompile(`<h1[^>]*class="[^"]*username[^"]*"[^>]*>([^<]+)</h1>`)
	if m := namePattern.FindStringSubmatch(content); len(m) > 1 {
		p.DisplayName = strings.TrimSpace(m[1])
	}

	// Extract avatar
	avatarPattern := regexp.MustCompile(`<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(content); len(m) > 1 {
		p.AvatarURL = m[1]
		if !strings.HasPrefix(p.AvatarURL, "http") {
			p.AvatarURL = "https://www.forosdelweb.com" + p.AvatarURL
		}
	}

	// Extract member since date
	datePattern := regexp.MustCompile(`(?i)(?:miembro desde|member since)[^>]*>([^<]+)</`)
	if m := datePattern.FindStringSubmatch(content); len(m) > 1 {
		p.CreatedAt = strings.TrimSpace(m[1])
	}

	// Extract post count
	postPattern := regexp.MustCompile(`(?i)(\d+)\s+(?:mensajes|posts)`)
	if m := postPattern.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["posts"] = m[1]
	}

	// Extract reputation/points
	repPattern := regexp.MustCompile(`(?i)(\d+)\s+(?:puntos|reputaci[oó]n|points)`)
	if m := repPattern.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["reputation"] = m[1]
	}

	// Extract location
	locPattern := regexp.MustCompile(`(?i)(?:ubicaci[oó]n|location)[^>]*>\s*([^<]+)</`)
	if m := locPattern.FindStringSubmatch(content); len(m) > 1 {
		loc := strings.TrimSpace(htmlutil.StripHTML(m[1]))
		if loc != "" {
			p.Location = loc
		}
	}

	// Extract bio/about
	bioPattern := regexp.MustCompile(`(?s)<div[^>]+class="[^"]*bio[^"]*"[^>]*>(.+?)</div>`)
	if m := bioPattern.FindStringSubmatch(content); len(m) > 1 {
		bio := htmlutil.StripHTML(m[1])
		bio = strings.TrimSpace(bio)
		if bio != "" {
			p.Bio = bio
		}
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	return p, nil
}

func extractUsername(urlStr string) string {
	// URL format: forosdelweb.com/miembros/username/
	// Extract: username
	if idx := strings.Index(urlStr, "/miembros/"); idx != -1 {
		username := urlStr[idx+len("/miembros/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}
	if idx := strings.Index(urlStr, "/members/"); idx != -1 {
		username := urlStr[idx+len("/members/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}
	return ""
}
