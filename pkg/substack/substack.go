// Package substack fetches Substack author profile data.
package substack

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

const platform = "substack"

// platformInfo implements profile.Platform for Substack.
type platformInfo struct{}

func (platformInfo) Name() string {
	return platform
}

func (platformInfo) Type() profile.PlatformType {
	return profile.PlatformTypeBlog
}

func (platformInfo) Match(url string) bool {
	return Match(url)
}

func (platformInfo) AuthRequired() bool {
	return AuthRequired()
}

func init() {
	profile.Register(platformInfo{})
}

// Match returns true if the URL is a Substack profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, ".substack.com") || (strings.Contains(lower, "substack.com/") && strings.Contains(lower, "/@"))
}

// AuthRequired returns false because Substack profiles are public.
func AuthRequired() bool { return false }

// Client handles Substack requests.
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

// New creates a Substack client.
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

// Fetch retrieves a Substack profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	// Use original URL if it's already a profile page, otherwise use /about
	fetchURL := urlStr
	if strings.Contains(urlStr, ".substack.com") && !strings.HasSuffix(urlStr, "/about") {
		fetchURL = fmt.Sprintf("https://%s.substack.com/about", username)
	}

	c.logger.InfoContext(ctx, "fetching substack profile", "url", fetchURL, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(string(body), urlStr, username)
}

// Patterns for extracting profile data.
var (
	metaAuthorPattern = regexp.MustCompile(`(?i)<meta\s+name=["']author["']\s+content=["']([^"']+)["']`)
	subscriberPattern = regexp.MustCompile(`([\d,]+)\s*(?:subscribers|Subscribers)`)
)

func parseProfile(html, url, username string) (*profile.Profile, error) {
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Try to extract from JSON-LD
	if ld := htmlutil.ExtractJSONLD(html); ld != "" {
		if name := extractFromJSONLD(ld, "name"); name != "" && name != "Substack" {
			prof.DisplayName = name
		}
		if image := extractFromJSONLD(ld, "image"); image != "" && !strings.Contains(image, "default") {
			prof.AvatarURL = image
		}
	}

	// Extract author name from meta author tag if still empty
	if prof.DisplayName == "" {
		if matches := metaAuthorPattern.FindStringSubmatch(html); len(matches) > 1 {
			author := strings.TrimSpace(matches[1])
			if author != "Substack" {
				prof.DisplayName = author
			}
		}
	}

	// Extract from og:title or title
	if prof.DisplayName == "" {
		title := htmlutil.Title(html)
		if title != "" {
			// Strip "About - " prefix
			title = strings.TrimPrefix(title, "About - ")

			parts := strings.Split(title, " | ")
			if len(parts) >= 2 {
				author := strings.TrimSpace(parts[0])
				if author != "Substack" && author != "" {
					prof.DisplayName = author
				}
			}
			if prof.DisplayName == "" && !strings.EqualFold(title, "Substack") {
				prof.DisplayName = strings.TrimSpace(title)
			}
		}
	}

	// Extract avatar from og:image if still empty
	if prof.AvatarURL == "" {
		if avatar := htmlutil.OGImage(html); avatar != "" && !strings.Contains(avatar, "substack-logo") {
			prof.AvatarURL = avatar
		}
	}

	// Extract bio/description
	if bio := htmlutil.Description(html); bio != "" && !htmlutil.IsGenericBio(bio) {
		prof.Bio = bio
	}

	// Try to extract subscriber count
	if matches := subscriberPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["subscribers"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(html)

	// Filter out Substack's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "substack.com") {
			filtered = append(filtered, link)
		}
	}
	prof.SocialLinks = filtered

	if prof.DisplayName == "" || prof.DisplayName == "Substack" {
		prof.DisplayName = username
	}

	return prof, nil
}

func extractFromJSONLD(ld, key string) string {
	pattern := regexp.MustCompile(`(?i)"` + regexp.QuoteMeta(key) + `"\s*:\s*"([^"]+)"`)
	if matches := pattern.FindStringSubmatch(ld); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func extractUsername(urlStr string) string {
	lower := strings.ToLower(urlStr)

	// Handle substack.com/@username
	if idx := strings.Index(lower, "substack.com/@"); idx != -1 {
		username := urlStr[idx+len("substack.com/@"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return username
	}

	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")

	// Extract username.substack.com pattern
	re := regexp.MustCompile(`^([^.]+)\.substack\.com`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
