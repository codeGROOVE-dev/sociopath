// Package nuget fetches NuGet (.NET package registry) profile data.
package nuget

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

const platform = "nuget"

// platformInfo implements profile.Platform for NuGet.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypePackage }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)nuget\.org/profiles/([a-zA-Z0-9_.-]+)`)

// Match returns true if the URL is a NuGet profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "nuget.org/profiles/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because NuGet profiles are public.
func AuthRequired() bool { return false }

// Client handles NuGet requests.
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

// New creates a NuGet client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
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

// Fetch retrieves a NuGet profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching nuget profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	prof := parseHTML(body, urlStr, username)

	return prof, nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	p := &profile.Profile{
		Platform:    platform,
		URL:         urlStr,
		Username:    username,
		DisplayName: username,
		Fields:      make(map[string]string),
	}

	// Extract display name from h1
	namePattern := regexp.MustCompile(`<h1[^>]*>\s*([^<]+?)\s*</h1>`)
	if m := namePattern.FindStringSubmatch(content); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" && name != username {
			p.DisplayName = name
		}
	}

	// Extract avatar
	avatarPattern := regexp.MustCompile(`<img[^>]+class="[^"]*profile-picture[^"]*"[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(content); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract website from links (look for personal website)
	websitePattern := regexp.MustCompile(`<a[^>]+href="(https?://[^"]+)"[^>]*>(?:Website|Homepage|Blog)</a>`)
	if m := websitePattern.FindStringSubmatch(content); len(m) > 1 {
		p.Website = m[1]
		if !contains(p.SocialLinks, m[1]) {
			p.SocialLinks = append(p.SocialLinks, m[1])
		}
	}

	// Extract packages from the page
	pkgPattern := regexp.MustCompile(`<a[^>]+href="/packages/([^/"]+)"[^>]*>([^<]*)</a>`)
	pkgMatches := pkgPattern.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	for _, m := range pkgMatches {
		if len(m) > 2 {
			pkgName := strings.TrimSpace(m[1])
			if pkgName != "" && !seen[pkgName] {
				seen[pkgName] = true
				post := profile.Post{
					Type:  profile.PostTypeRepository,
					Title: pkgName,
					URL:   fmt.Sprintf("https://www.nuget.org/packages/%s", pkgName),
				}
				p.Posts = append(p.Posts, post)
			}
		}
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

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
