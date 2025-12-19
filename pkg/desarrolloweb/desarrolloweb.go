// Package desarrolloweb fetches DesarrolloWeb.com user profile data.
package desarrolloweb

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

const platform = "desarrolloweb"

// platformInfo implements profile.Platform for DesarrolloWeb.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a DesarrolloWeb profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "desarrolloweb.com/autor/") ||
		strings.Contains(lower, "desarrolloweb.com/usuarios/") ||
		strings.Contains(lower, "desarrolloweb.com/perfil/")
}

// AuthRequired returns false for now.
func AuthRequired() bool { return false }

// Client handles DesarrolloWeb requests.
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

// New creates a DesarrolloWeb client.
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

// Fetch retrieves a DesarrolloWeb profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching desarrolloweb profile", "url", urlStr, "username", username)

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
	if strings.Contains(content, "no encontrado") || strings.Contains(content, "not found") {
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
	namePattern := regexp.MustCompile(`<h1[^>]*>(?:Autor:|Author:)?\s*([^<]+)</h1>`)
	if m := namePattern.FindStringSubmatch(content); len(m) > 1 {
		p.DisplayName = strings.TrimSpace(m[1])
	}

	// Try alternative name pattern from meta tags
	if p.DisplayName == "" {
		metaPattern := regexp.MustCompile(`<meta[^>]+(?:name|property)="(?:author|og:title)"[^>]+content="([^"]+)"`)
		if m := metaPattern.FindStringSubmatch(content); len(m) > 1 {
			p.DisplayName = strings.TrimSpace(m[1])
		}
	}

	// Extract avatar
	avatarPattern := regexp.MustCompile(`<img[^>]+class="[^"]*(?:avatar|author-photo)[^"]*"[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(content); len(m) > 1 {
		p.AvatarURL = m[1]
		if !strings.HasPrefix(p.AvatarURL, "http") {
			p.AvatarURL = "https://desarrolloweb.com" + p.AvatarURL
		}
	}

	// Extract bio/description
	bioPattern := regexp.MustCompile(`(?s)<div[^>]+class="[^"]*(?:bio|author-bio|descripcion)[^"]*"[^>]*>(.+?)</div>`)
	if m := bioPattern.FindStringSubmatch(content); len(m) > 1 {
		bio := htmlutil.StripHTML(m[1])
		bio = strings.TrimSpace(bio)
		if bio != "" {
			p.Bio = bio
		}
	}

	// Extract article count
	if m := regexp.MustCompile(`(?i)(\d+)\s+(?:art[ií]culos|articles)`).FindStringSubmatch(content); len(m) > 1 {
		p.Fields["articles"] = m[1]
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract website
	websitePattern := regexp.MustCompile(`(?i)(?:sitio web|website)[^>]*href="([^"]+)"`)
	if m := websitePattern.FindStringSubmatch(content); len(m) > 1 {
		website := strings.TrimSpace(m[1])
		if website != "" && !strings.Contains(website, "desarrolloweb.com") {
			p.Website = website
		}
	}

	return p, nil
}

func extractUsername(urlStr string) string {
	patterns := []string{
		"/autor/",
		"/usuarios/",
		"/perfil/",
		"/author/",
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
