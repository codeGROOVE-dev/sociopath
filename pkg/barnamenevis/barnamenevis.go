// Package barnamenevis fetches Barnamenevis forum profile data.
// Barnamenevis is the largest Persian programming forum (350K+ users, 1M+ posts).
package barnamenevis

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

const platform = "barnamenevis"

// Pre-compiled patterns for URL matching and extraction.
var (
	memberPattern = regexp.MustCompile(`barnamenevis\.org/member\.php\?(\d+)`)
	postCountPattern = regexp.MustCompile(`(\d+(?:,\d+)*)\s*(?:پاسخ|Posts|Responses)`)
	joinDatePattern = regexp.MustCompile(`(?:تاریخ عضویت|Join Date)[:\s]*([^<\n]+)`)
	locationPattern = regexp.MustCompile(`(?:موقعیت|Location)[:\s]*([^<\n]+)`)
)

// platformInfo implements profile.Platform for Barnamenevis.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Barnamenevis member profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "barnamenevis.org/member.php")
}

// AuthRequired returns false because Barnamenevis profiles are public.
func AuthRequired() bool { return false }

// Client handles Barnamenevis requests.
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

// New creates a Barnamenevis client.
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

// Fetch retrieves a Barnamenevis forum profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	userID := extractUserID(urlStr)
	if userID == "" {
		return nil, fmt.Errorf("could not extract user ID from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching barnamenevis profile", "url", urlStr, "user_id", userID)

	// Normalize URL to just the user ID
	profileURL := fmt.Sprintf("https://barnamenevis.org/member.php?%s", userID)

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

// extractUserID extracts the user ID from a Barnamenevis URL.
func extractUserID(urlStr string) string {
	matches := memberPattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractFromHTML extracts profile data from vBulletin HTML content.
func extractFromHTML(p *profile.Profile, body []byte) {
	html := string(body)

	// Extract display name from page title or h1
	namePatterns := []string{
		`<title>([^<]+?)\s*-\s*برنامه`,
		`<h1[^>]*>([^<]+)</h1>`,
		`class="[^"]*member[_-]username[^"]*"[^>]*>([^<]+)<`,
	}
	for _, pattern := range namePatterns {
		if matches := regexp.MustCompile(pattern).FindStringSubmatch(html); len(matches) > 1 {
			name := htmlutil.DecodeHTMLEntities(strings.TrimSpace(matches[1]))
			if name != "" && !strings.Contains(name, "برنامه نویس") {
				p.DisplayName = name
				break
			}
		}
	}

	// Extract bio/about from profile sections
	bioPatterns := []string{
		`(?s)(?:درباره من|About Me|Biography)[:\s]*<[^>]+>([^<]+)<`,
		`(?s)class="[^"]*about[^"]*"[^>]*>(.+?)</div>`,
		`(?s)(?:علاقه‌مندی|Interests?)[:\s]*([^<\n]{10,200})`,
	}
	var bioSections []string
	for _, pattern := range bioPatterns {
		if matches := regexp.MustCompile(pattern).FindAllStringSubmatch(html, -1); len(matches) > 0 {
			for _, m := range matches {
				if len(m) > 1 {
					section := htmlutil.DecodeHTMLEntities(htmlutil.StripHTML(m[1]))
					section = strings.TrimSpace(section)
					if len(section) > 10 && len(section) < 500 {
						bioSections = append(bioSections, section)
					}
				}
			}
		}
	}
	if len(bioSections) > 0 {
		p.Bio = strings.Join(bioSections, " | ")
	}

	// Extract location
	if matches := locationPattern.FindStringSubmatch(html); len(matches) > 1 {
		location := htmlutil.DecodeHTMLEntities(strings.TrimSpace(matches[1]))
		location = htmlutil.StripHTML(location)
		if location != "" && location != "-" {
			p.Location = location
		}
	}

	// Extract avatar
	avatarPatterns := []string{
		`<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`,
		`customavatars/avatar\d+_\d+\.(?:jpg|png|gif)`,
	}
	for _, pattern := range avatarPatterns {
		if matches := regexp.MustCompile(pattern).FindStringSubmatch(html); len(matches) > 0 {
			avatarPath := matches[len(matches)-1]
			if strings.HasPrefix(avatarPath, "/") {
				p.AvatarURL = "https://barnamenevis.org" + avatarPath
			} else if !strings.HasPrefix(avatarPath, "http") {
				p.AvatarURL = "https://barnamenevis.org/" + avatarPath
			} else {
				p.AvatarURL = avatarPath
			}
			break
		}
	}

	// Extract post count
	if matches := postCountPattern.FindStringSubmatch(html); len(matches) > 1 {
		postCount := strings.ReplaceAll(matches[1], ",", "")
		p.Fields["post_count"] = postCount
	}

	// Extract join date
	if matches := joinDatePattern.FindStringSubmatch(html); len(matches) > 1 {
		joinDate := htmlutil.DecodeHTMLEntities(strings.TrimSpace(matches[1]))
		joinDate = htmlutil.StripHTML(joinDate)
		if joinDate != "" {
			p.Fields["joined"] = joinDate
		}
	}

	// Extract age/birth year if present
	agePattern := regexp.MustCompile(`(?:سن|Age)[:\s]*(\d+)`)
	if matches := agePattern.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["age"] = matches[1]
	}

	// Extract role/title (admin, moderator, etc.)
	rolePatterns := []string{
		`(?:بنیان گذار|Administrator|Moderator|مدیر)`,
		`class="[^"]*usertitle[^"]*"[^>]*>([^<]+)<`,
	}
	for _, pattern := range rolePatterns {
		if matches := regexp.MustCompile(pattern).FindStringSubmatch(html); len(matches) > 0 {
			role := htmlutil.DecodeHTMLEntities(strings.TrimSpace(matches[len(matches)-1]))
			if role != "" && len(role) < 100 {
				p.Fields["role"] = role
				break
			}
		}
	}

	// Extract profession/occupation
	professionPatterns := []string{
		`(?s)(?:شغل|Occupation)[:\s]*([^<\n]{3,100})`,
		`(?:مدرس|استاد|معلم|برنامه نویس|Developer|Programmer|Teacher)`,
	}
	for _, pattern := range professionPatterns {
		if matches := regexp.MustCompile(pattern).FindStringSubmatch(html); len(matches) > 0 {
			profession := htmlutil.DecodeHTMLEntities(htmlutil.StripHTML(matches[len(matches)-1]))
			profession = strings.TrimSpace(profession)
			if profession != "" && len(profession) < 200 {
				p.Fields["profession"] = profession
				break
			}
		}
	}

	// Extract social links and contact info
	p.SocialLinks = extractSocialLinks(html)

	// Extract website
	websitePattern := regexp.MustCompile(`(?:وب‌سایت|Website|Homepage)[:\s]*<a[^>]+href="([^"]+)"`)
	if matches := websitePattern.FindStringSubmatch(html); len(matches) > 1 {
		website := strings.TrimSpace(matches[1])
		if !strings.Contains(website, "barnamenevis.org") {
			p.Website = website
		}
	}

	// Extract skills from bio or interests
	skillPattern := regexp.MustCompile(`(?i)\b(ASP\.NET|C#|PHP|Python|Java|JavaScript|SQL|MySQL|Laravel|Django|React|Vue|Angular|\.NET|MVC|Web|Android|iOS|Mobile)\b`)
	skills := skillPattern.FindAllString(html, -1)
	if len(skills) > 0 {
		seen := make(map[string]bool)
		var uniqueSkills []string
		for _, skill := range skills {
			skillKey := strings.ToLower(skill)
			if !seen[skillKey] && len(uniqueSkills) < 10 {
				seen[skillKey] = true
				uniqueSkills = append(uniqueSkills, skill)
			}
		}
		if len(uniqueSkills) > 0 {
			p.Fields["skills"] = strings.Join(uniqueSkills, ", ")
		}
	}
}

// extractSocialLinks finds social media links and contact info.
func extractSocialLinks(html string) []string {
	var links []string
	seen := make(map[string]bool)

	// GitHub links
	if matches := regexp.MustCompile(`github\.com/([a-zA-Z0-9_-]+)`).FindAllStringSubmatch(html, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) > 1 {
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
			if len(m) > 1 && m[1] != "share" {
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
