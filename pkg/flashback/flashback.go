// Package flashback fetches Flashback profile data.
package flashback

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "flashback"

// platformInfo implements profile.Platform for Flashback.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Flashback profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "flashback.org") {
		return false
	}
	// Match profile URLs: /member.php?u=userid or /members/username or similar
	if strings.Contains(lower, "/member") || strings.Contains(lower, "/profil") {
		return true
	}
	return false
}

// AuthRequired returns false because Flashback profiles are public.
func AuthRequired() bool { return false }

// Client handles Flashback requests.
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

// New creates a Flashback client.
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

// Fetch retrieves a Flashback profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username, userid := extractUsernameOrID(urlStr)
	if username == "" && userid == "" {
		return nil, fmt.Errorf("could not extract username or userid from: %s", urlStr)
	}

	// Use the original URL as-is since Flashback may use different URL patterns
	normalizedURL := urlStr
	c.logger.InfoContext(ctx, "fetching flashback profile", "url", normalizedURL, "username", username, "userid", userid)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(string(body), normalizedURL, username)
}

func parseProfile(html, url, username string) (*profile.Profile, error) {
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract title
	prof.PageTitle = htmlutil.Title(html)

	// Extract display name from profile header
	// Try various patterns
	namePatterns := []string{
		`(?i)<h1[^>]*>\s*([^<]+)\s*</h1>`,
		`(?i)<div[^>]*class="[^"]*username[^"]*"[^>]*>\s*([^<]+)\s*</div>`,
		`(?i)<span[^>]*class="[^"]*username[^"]*"[^>]*>\s*([^<]+)\s*</span>`,
	}

	for _, pattern := range namePatterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(html); len(matches) > 1 {
			name := strings.TrimSpace(matches[1])
			if name != "" && !strings.Contains(strings.ToLower(name), "error") {
				prof.DisplayName = name
				break
			}
		}
	}

	// Try title as fallback
	if prof.DisplayName == "" && prof.PageTitle != "" {
		if idx := strings.Index(prof.PageTitle, " - "); idx != -1 {
			name := strings.TrimSpace(prof.PageTitle[:idx])
			if name != "" && !strings.Contains(strings.ToLower(name), "error") {
				prof.DisplayName = name
			}
		}
	}

	// Fallback to username
	if prof.DisplayName == "" && username != "" {
		prof.DisplayName = username
	}

	// Extract bio/about
	bioPattern := regexp.MustCompile(`(?is)<div[^>]*class="[^"]*(?:about|bio|description)[^"]*"[^>]*>(.*?)</div>`)
	if matches := bioPattern.FindStringSubmatch(html); len(matches) > 1 {
		bio := htmlutil.StripTags(matches[1])
		bio = strings.TrimSpace(bio)
		bio = regexp.MustCompile(`\s+`).ReplaceAllString(bio, " ")
		if bio != "" && len(bio) > 10 {
			prof.Bio = bio
		}
	}

	// Try meta description if no bio found
	if prof.Bio == "" {
		prof.Bio = htmlutil.Description(html)
	}

	// Extract location
	locationPattern := regexp.MustCompile(`(?is)<dt[^>]*>(?:Location|Plats|Ort)[^<]*</dt>\s*<dd[^>]*>(.*?)</dd>`)
	if matches := locationPattern.FindStringSubmatch(html); len(matches) > 1 {
		loc := htmlutil.StripTags(matches[1])
		loc = strings.TrimSpace(loc)
		if loc != "" {
			prof.Location = loc
		}
	}

	// Extract website/homepage
	websitePattern := regexp.MustCompile(`(?is)<dt[^>]*>(?:Website|Hemsida)[^<]*</dt>\s*<dd[^>]*>.*?href="([^"]+)"`)
	if matches := websitePattern.FindStringSubmatch(html); len(matches) > 1 {
		website := strings.TrimSpace(matches[1])
		if website != "" && !strings.Contains(website, "flashback.org") {
			prof.Website = website
		}
	}

	// Extract social links from the page
	pageLinks := htmlutil.SocialLinks(html)
	for _, link := range pageLinks {
		// Skip internal links and assets
		if strings.Contains(link, "flashback.org") ||
			strings.Contains(link, "favicon") ||
			strings.HasSuffix(link, ".ico") || strings.HasSuffix(link, ".svg") ||
			strings.HasSuffix(link, ".png") || strings.HasSuffix(link, ".jpg") {
			continue
		}
		if !slices.Contains(prof.SocialLinks, link) {
			prof.SocialLinks = append(prof.SocialLinks, link)
		}
	}

	// Extract post count
	postsPattern := regexp.MustCompile(`(?i)(\d+)\s*(?:inlägg|post|message)`)
	if matches := postsPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["posts"] = matches[1]
	}

	// Extract join date
	joinPattern := regexp.MustCompile(`(?is)<dt[^>]*>(?:Joined|Medlem sedan|Registrerad)[^<]*</dt>\s*<dd[^>]*>(.*?)</dd>`)
	if matches := joinPattern.FindStringSubmatch(html); len(matches) > 1 {
		joined := htmlutil.StripTags(matches[1])
		joined = strings.TrimSpace(joined)
		if joined != "" {
			prof.Fields["joined"] = joined
		}
	}

	if prof.DisplayName == "" {
		return nil, errors.New("failed to extract profile name")
	}

	return prof, nil
}

func extractUsernameOrID(urlStr string) (username, userid string) {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "www.")

	// Try to extract userid from member.php?u=123
	re := regexp.MustCompile(`member\.php\?u=(\d+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return "", matches[1]
	}

	// Try to extract username from /members/username or /profil/username
	re = regexp.MustCompile(`/(?:members|profil)/([^/?#]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1], ""
	}

	return "", ""
}
