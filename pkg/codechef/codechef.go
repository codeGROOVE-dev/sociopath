// Package codechef fetches CodeChef user profile data.
package codechef

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

const platform = "codechef"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)codechef\.com/users/([a-zA-Z0-9_]+)`)

// Match returns true if the URL is a CodeChef profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "codechef.com") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because CodeChef profiles are public.
func AuthRequired() bool { return false }

// Client handles CodeChef requests.
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

// New creates a CodeChef client.
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

var (
	displayNamePattern = regexp.MustCompile(`(?i)<h1[^>]*class="h2-style"[^>]*>([^<]+)</h1>`)
	ratingPattern      = regexp.MustCompile(`(?i)<div[^>]*class="rating-number"[^>]*>(\d+)</div>`)
	starsPattern       = regexp.MustCompile(`(?i)<span[^>]*class="rating"[^>]*>([^<]+)</span>`)
	countryPattern     = regexp.MustCompile(`(?i)<span[^>]*class="user-country-name"[^>]*>([^<]+)</span>`)
	avatarPattern      = regexp.MustCompile(`(?i)<img[^>]+class="profileImage"[^>]+src="([^"]+)"`)
	institutionPattern = regexp.MustCompile(`(?i)<span[^>]*>([^<]*University[^<]*|[^<]*Institute[^<]*|[^<]*College[^<]*)</span>`)
	globalRankPattern  = regexp.MustCompile(`(?i)Global Rank[^<]*<[^>]*>[^<]*<strong>(\d+)</strong>`)
	countryRankPattern = regexp.MustCompile(`(?i)Country Rank[^<]*<[^>]*>[^<]*<strong>(\d+)</strong>`)
	bioPattern         = regexp.MustCompile(`(?i)<div[^>]*class="[^"]*user.*details.*bio[^"]*"[^>]*>([^<]+)</div>`)
	websitePattern     = regexp.MustCompile(`(?i)(?:Website|Homepage):\s*<a[^>]+href="(https?://[^"]+)"`)
	problemsPattern    = regexp.MustCompile(`(?i)>(\w+)\s+Problems\s+Solved<[^>]*>[^<]*<b>(\d+)</b>`)
)

// Fetch retrieves a CodeChef profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching codechef profile", "url", urlStr, "username", username)

	profileURL := "https://www.codechef.com/users/" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Referer", "https://www.codechef.com/")
	req.Header.Set("DNT", "1")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	content := string(body)

	// Check if profile exists
	if htmlutil.IsNotFound(content) {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(content, username, urlStr)
}

func parseProfile(htmlContent, username, url string) (*profile.Profile, error) {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract display name
	if m := displayNamePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		name := strings.TrimSpace(m[1])
		if name != "" && name != username && !strings.Contains(name, "CodeChef") {
			p.DisplayName = name
		}
	}

	// If no display name found, it might be a generic page
	if p.DisplayName == "" {
		// Verify if this is actually a user profile by looking for other indicators
		if !strings.Contains(htmlContent, "Rating:") && !strings.Contains(htmlContent, "Global Rank") {
			return nil, profile.ErrProfileNotFound
		}
		p.DisplayName = username
	}

	// Extract avatar
	if m := avatarPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		avatarURL := m[1]
		if !strings.Contains(avatarURL, "default") {
			p.AvatarURL = avatarURL
		}
	}

	// Extract country
	if m := countryPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract rating
	if m := ratingPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		p.Fields["rating"] = m[1]
	}

	// Extract star rating
	if m := starsPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		stars := strings.TrimSpace(m[1])
		if stars != "" {
			p.Fields["stars"] = stars
		}
	}

	// Extract institution
	if m := institutionPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		inst := strings.TrimSpace(m[1])
		if inst != "" {
			p.Groups = append(p.Groups, inst)
			p.Fields["institution"] = inst
		}
	}

	// Extract global rank
	if m := globalRankPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		p.Fields["global_rank"] = m[1]
	}

	// Extract country rank
	if m := countryRankPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		p.Fields["country_rank"] = m[1]
	}

	// Extract bio/description
	if m := bioPattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		bioText := strings.TrimSpace(html.UnescapeString(m[1]))
		if bioText != "" {
			p.Bio = bioText
		}
	}

	// Extract website
	if m := websitePattern.FindStringSubmatch(htmlContent); len(m) > 1 {
		website := strings.TrimSpace(m[1])
		if website != "" {
			p.Website = website
		}
	}

	// Extract problems solved stats
	matches := problemsPattern.FindAllStringSubmatch(htmlContent, -1)
	for _, m := range matches {
		if len(m) > 2 {
			difficulty := strings.ToLower(strings.TrimSpace(m[1]))
			count := strings.TrimSpace(m[2])
			if difficulty != "" && count != "0" {
				p.Fields[difficulty+"_problems"] = count
			}
		}
	}

	// Extract social media links
	socialLinks := htmlutil.SocialLinks(htmlContent)
	if len(socialLinks) > 0 {
		p.SocialLinks = socialLinks
	}

	return p, nil
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
