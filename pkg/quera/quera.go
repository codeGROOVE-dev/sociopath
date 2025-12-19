// Package quera fetches Quera profile data.
// Quera is Iran's largest programmer community and education platform.
package quera

import (
	"context"
	"encoding/json"
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

const platform = "quera"

// Pre-compiled patterns for URL matching and extraction.
var (
	profilePattern = regexp.MustCompile(`quera\.org/profile/([a-z0-9]+)`)
	locationPattern = regexp.MustCompile(`(?:Location|موقعیت)[:\s]+([^<\n]+)`)
	skillsPattern = regexp.MustCompile(`(?:Skills|مهارت‌ها)[:\s]+([^<\n]+)`)
)

// platformInfo implements profile.Platform for Quera.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Quera profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "quera.org/profile/")
}

// AuthRequired returns false because Quera profiles are public.
func AuthRequired() bool { return false }

// Client handles Quera requests.
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

// New creates a Quera client.
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

// Fetch retrieves a Quera profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	userID := extractUserID(urlStr)
	if userID == "" {
		return nil, fmt.Errorf("could not extract user ID from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching quera profile", "url", urlStr, "user_id", userID)

	// Normalize URL
	profileURL := fmt.Sprintf("https://quera.org/profile/%s", userID)

	// Fetch HTML
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "fa,en;q=0.9")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	p := &profile.Profile{
		Platform:   platform,
		URL:        profileURL,
		Username:   userID,
		Confidence: 1.0,
		Fields:     make(map[string]string),
	}

	// Extract data from HTML
	extractFromHTML(p, body)

	return p, nil
}

// extractUserID extracts the user ID from a Quera URL.
func extractUserID(urlStr string) string {
	matches := profilePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractFromHTML extracts profile data from HTML content.
func extractFromHTML(p *profile.Profile, body []byte) {
	html := string(body)

	// Extract JSON-LD structured data if present
	if jsonData := htmlutil.ExtractJSONLD(html); jsonData != "" {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(jsonData), &data); err == nil {
			if name, ok := data["name"].(string); ok {
				p.DisplayName = strings.TrimSpace(name)
			}
			if desc, ok := data["description"].(string); ok {
				p.Bio = strings.TrimSpace(desc)
			}
			if img, ok := data["image"].(string); ok {
				if strings.HasPrefix(img, "/") {
					p.AvatarURL = "https://quera.org" + img
				} else {
					p.AvatarURL = img
				}
			}
		}
	}

	// Extract display name from various patterns
	if p.DisplayName == "" {
		if name := htmlutil.ExtractMetaTag(html, "og:title"); name != "" {
			p.DisplayName = strings.TrimSpace(name)
		}
	}

	// Extract from h1 or profile name elements
	if p.DisplayName == "" {
		namePatterns := []string{
			`<h1[^>]*>([^<]+)</h1>`,
			`class="[^"]*profile[_-]name[^"]*"[^>]*>([^<]+)<`,
			`class="[^"]*user[_-]name[^"]*"[^>]*>([^<]+)<`,
		}
		for _, pattern := range namePatterns {
			if matches := regexp.MustCompile(pattern).FindStringSubmatch(html); len(matches) > 1 {
				name := htmlutil.DecodeHTMLEntities(strings.TrimSpace(matches[1]))
				if name != "" {
					p.DisplayName = name
					break
				}
			}
		}
	}

	// Extract bio/description
	if p.Bio == "" {
		if desc := htmlutil.ExtractMetaTag(html, "og:description"); desc != "" {
			p.Bio = strings.TrimSpace(desc)
		}
	}

	// Extract bio from profile sections
	if p.Bio == "" {
		bioPatterns := []string{
			`(?s)class="[^"]*bio[^"]*"[^>]*>([^<]+)<`,
			`(?s)class="[^"]*description[^"]*"[^>]*>([^<]+)<`,
			`(?s)class="[^"]*about[^"]*"[^>]*>(.+?)</`,
		}
		for _, pattern := range bioPatterns {
			if matches := regexp.MustCompile(pattern).FindStringSubmatch(html); len(matches) > 1 {
				bio := htmlutil.DecodeHTMLEntities(htmlutil.StripHTML(matches[1]))
				bio = strings.TrimSpace(bio)
				if len(bio) > 10 {
					p.Bio = bio
					break
				}
			}
		}
	}

	// Extract avatar
	if p.AvatarURL == "" {
		if img := htmlutil.ExtractMetaTag(html, "og:image"); img != "" {
			p.AvatarURL = img
		}
	}

	// Extract avatar from CACHE pattern
	if p.AvatarURL == "" {
		avatarPatterns := []string{
			`/media/CACHE/images/public/avatars/[^"'\s]+\.jpg`,
			`/media/public/avatars/[^"'\s]+\.[a-z]+`,
			`class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`,
		}
		for _, pattern := range avatarPatterns {
			if matches := regexp.MustCompile(pattern).FindStringSubmatch(html); len(matches) > 0 {
				avatarPath := matches[len(matches)-1]
				if strings.HasPrefix(avatarPath, "/") {
					p.AvatarURL = "https://quera.org" + avatarPath
				} else {
					p.AvatarURL = avatarPath
				}
				break
			}
		}
	}

	// Extract location
	if matches := locationPattern.FindStringSubmatch(html); len(matches) > 1 {
		location := htmlutil.DecodeHTMLEntities(strings.TrimSpace(matches[1]))
		if location != "" {
			p.Location = location
		}
	}

	// Extract location from structured patterns
	if p.Location == "" {
		locPatterns := []string{
			`(?s)<[^>]*location[^>]*>([^<]+)<`,
			`(?s)تهران|اصفهان|مشهد|شیراز|تبریز`,
		}
		for _, pattern := range locPatterns {
			if matches := regexp.MustCompile(pattern).FindStringSubmatch(html); len(matches) > 0 {
				location := htmlutil.DecodeHTMLEntities(strings.TrimSpace(matches[len(matches)-1]))
				if location != "" && len(location) < 100 {
					p.Location = location
					break
				}
			}
		}
	}

	// Extract title/headline
	titlePatterns := []string{
		`(?:Title|عنوان|Headline)[:\s]*([^<\n]+)`,
		`class="[^"]*title[^"]*"[^>]*>([^<]+)<`,
		`برنامه نویس|توسعه دهنده|Developer|Programmer|Engineer`,
	}
	for _, pattern := range titlePatterns {
		if matches := regexp.MustCompile(pattern).FindStringSubmatch(html); len(matches) > 0 {
			title := htmlutil.DecodeHTMLEntities(strings.TrimSpace(matches[len(matches)-1]))
			if title != "" && len(title) < 200 {
				p.Fields["title"] = title
				break
			}
		}
	}

	// Extract skills
	if matches := skillsPattern.FindStringSubmatch(html); len(matches) > 1 {
		skills := strings.TrimSpace(matches[1])
		p.Fields["skills"] = skills
	}

	// Extract skills from structured lists
	if p.Fields["skills"] == "" {
		skillPattern := regexp.MustCompile(`(?i)(?:PHP|Java|Python|JavaScript|C\+\+|C#|Go|Rust|Ruby|Swift|Kotlin|HTML|CSS|SQL|MySQL|MongoDB|Laravel|Django|React|Vue|Angular|Git|Docker|Kubernetes)`)
		skills := skillPattern.FindAllString(html, -1)
		if len(skills) > 0 {
			seen := make(map[string]bool)
			var uniqueSkills []string
			for _, skill := range skills {
				skillLower := strings.ToLower(skill)
				if !seen[skillLower] && len(uniqueSkills) < 15 {
					seen[skillLower] = true
					uniqueSkills = append(uniqueSkills, skill)
				}
			}
			if len(uniqueSkills) > 0 {
				p.Fields["skills"] = strings.Join(uniqueSkills, ", ")
			}
		}
	}

	// Extract social links
	p.SocialLinks = extractSocialLinks(html)

	// Extract website from profile
	websitePattern := regexp.MustCompile(`(?i)(?:website|وب‌سایت)[:\s]*<a[^>]+href="([^"]+)"`)
	if matches := websitePattern.FindStringSubmatch(html); len(matches) > 1 {
		p.Website = strings.TrimSpace(matches[1])
	}
}

// extractSocialLinks finds social media links in the profile.
func extractSocialLinks(html string) []string {
	var links []string
	seen := make(map[string]bool)

	// GitHub links
	if matches := regexp.MustCompile(`github\.com/([a-zA-Z0-9_-]+)`).FindAllStringSubmatch(html, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) > 1 && m[1] != "share" && m[1] != "quera" && m[1] != "querateam" {
				link := "https://github.com/" + m[1]
				if !seen[link] {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	// LinkedIn links
	if matches := regexp.MustCompile(`linkedin\.com/in/([a-zA-Z0-9_-]+)`).FindAllStringSubmatch(html, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) > 1 {
				link := "https://linkedin.com/in/" + m[1]
				if !seen[link] {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	// Twitter/X links
	if matches := regexp.MustCompile(`(?:twitter\.com|x\.com)/([a-zA-Z0-9_]+)`).FindAllStringSubmatch(html, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) > 1 && m[1] != "share" && m[1] != "intent" {
				link := "https://twitter.com/" + m[1]
				if !seen[link] {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	// Telegram links
	if matches := regexp.MustCompile(`t\.me/([a-zA-Z0-9_]+)`).FindAllStringSubmatch(html, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) > 1 {
				link := "https://t.me/" + m[1]
				if !seen[link] {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	// Instagram links
	if matches := regexp.MustCompile(`instagram\.com/([a-zA-Z0-9_.]+)`).FindAllStringSubmatch(html, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) > 1 {
				link := "https://instagram.com/" + m[1]
				if !seen[link] {
					seen[link] = true
					links = append(links, link)
				}
			}
		}
	}

	return links
}
