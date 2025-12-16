// Package pypi fetches PyPI user profile data.
package pypi

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const (
	platform  = "pypi"
	userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
)

// Pre-compiled regex patterns for HTML parsing.
var (
	nameRe     = regexp.MustCompile(`<h1\s+class="author-profile__name">([^<]+)</h1>`)
	avatarRe   = regexp.MustCompile(`<img\s+src="([^"]+)"[^>]*alt="Avatar for`)
	projectRe  = regexp.MustCompile(`<h2>\s*(\d+)\s*projects?\s*</h2>`)
	packageRe  = regexp.MustCompile(`<a\s+class="package-snippet"\s+href="(/project/[^/]+/)">`)
	titleRe    = regexp.MustCompile(`<h3\s+class="package-snippet__title">([^<]+)</h3>`)
	descRe     = regexp.MustCompile(`<p\s+class="package-snippet__description">([^<]+)</p>`)
	usernameRe = regexp.MustCompile(`pypi\.org/user/([^/?]+)`)
)

// platformInfo implements profile.Platform for PyPI.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a PyPI user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "pypi.org/user/") {
		return false
	}
	// Extract username path
	idx := strings.Index(lower, "pypi.org/user/")
	path := lower[idx+len("pypi.org/user/"):]
	// Remove query string first
	if qIdx := strings.Index(path, "?"); qIdx >= 0 {
		path = path[:qIdx]
	}
	// Then remove trailing slash
	path = strings.TrimSuffix(path, "/")
	// Must be just username (no slashes)
	if strings.Contains(path, "/") {
		return false
	}
	return path != ""
}

// AuthRequired returns false because PyPI profiles are public.
func AuthRequired() bool { return false }

// Client handles PyPI requests.
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

// New creates a PyPI client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a PyPI user profile.
func (c *Client) Fetch(ctx context.Context, url string) (*profile.Profile, error) {
	user := extractUsername(url)
	if user == "" {
		return nil, fmt.Errorf("could not extract username from: %s", url)
	}

	// Normalize URL
	url = "https://pypi.org/user/" + user + "/"

	c.logger.InfoContext(ctx, "fetching pypi profile", "url", url, "username", user)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}

	// PyPI requires specific headers to bypass bot protection
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	// Check if we got a bot protection page
	s := string(body)
	if strings.Contains(strings.ToLower(s), "client challenge") {
		return nil, errors.New("pypi bot protection triggered")
	}

	p := parseHTML(body, url, user)
	if p.DisplayName == "" && p.Username == user {
		// Check if this is a 404 page or profile not found
		if strings.Contains(s, "Page Not Found") || strings.Contains(s, "404") {
			return nil, profile.ErrProfileNotFound
		}
	}

	return p, nil
}

func parseHTML(data []byte, url, user string) *profile.Profile {
	s := string(data)

	p := &profile.Profile{
		Platform:      platform,
		URL:           url,
		Authenticated: false,
		Username:      user,
		Fields:        make(map[string]string),
	}

	// Extract name from h1.author-profile__name
	if m := nameRe.FindStringSubmatch(s); len(m) > 1 {
		p.DisplayName = strings.TrimSpace(html.UnescapeString(m[1]))
	}

	// Extract avatar URL
	if m := avatarRe.FindStringSubmatch(s); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	// Extract project count
	if m := projectRe.FindStringSubmatch(s); len(m) > 1 {
		p.Fields["projects"] = m[1]
	}

	// Extract packages
	pkgs := packageRe.FindAllStringSubmatchIndex(s, -1)
	titles := titleRe.FindAllStringSubmatch(s, -1)
	descs := descRe.FindAllStringSubmatch(s, -1)

	for i, pm := range pkgs {
		if i >= len(titles) {
			break
		}

		pkgURL := "https://pypi.org" + s[pm[2]:pm[3]]
		title := html.UnescapeString(titles[i][1])

		var desc string
		if i < len(descs) {
			desc = html.UnescapeString(descs[i][1])
		}

		p.Posts = append(p.Posts, profile.Post{
			Type:    "repository",
			Title:   title,
			Content: desc,
			URL:     pkgURL,
		})
	}

	return p
}

func extractUsername(s string) string {
	// Remove protocol
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "www.")

	// Extract pypi.org/user/username
	if m := usernameRe.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}

	return ""
}
