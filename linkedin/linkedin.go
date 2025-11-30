// Package linkedin fetches LinkedIn user profile data using authenticated session cookies.
package linkedin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/auth"
	"github.com/codeGROOVE-dev/sociopath/cache"
	"github.com/codeGROOVE-dev/sociopath/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/profile"
)

const platform = "linkedin"

// Match returns true if the URL is a LinkedIn profile URL.
func Match(urlStr string) bool {
	return strings.Contains(strings.ToLower(urlStr), "linkedin.com/in/")
}

// AuthRequired returns true because LinkedIn requires authentication.
func AuthRequired() bool { return true }

// Client handles LinkedIn requests with authenticated cookies.
type Client struct {
	httpClient *http.Client
	cache      cache.HTTPCache
	logger     *slog.Logger
	debug      bool
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cookies        map[string]string
	cache          cache.HTTPCache
	logger         *slog.Logger
	browserCookies bool
}

// WithCookies sets explicit cookie values.
func WithCookies(cookies map[string]string) Option {
	return func(c *config) { c.cookies = cookies }
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache cache.HTTPCache) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithBrowserCookies enables reading cookies from browser stores.
func WithBrowserCookies() Option {
	return func(c *config) { c.browserCookies = true }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates a LinkedIn client.
// Cookie sources are checked in order: WithCookies > environment > browser.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	// Build cookie sources chain
	var sources []auth.Source
	if len(cfg.cookies) > 0 {
		sources = append(sources, auth.NewStaticSource(cfg.cookies))
	}
	sources = append(sources, auth.EnvSource{})
	if cfg.browserCookies {
		sources = append(sources, auth.NewBrowserSource(cfg.logger))
	}

	cookies, err := auth.ChainSources(ctx, platform, sources...)
	if err != nil {
		return nil, fmt.Errorf("cookie retrieval failed: %w", err)
	}
	if len(cookies) == 0 {
		envVars := auth.EnvVarsForPlatform(platform)
		return nil, fmt.Errorf("%w: set %v or use WithCookies/WithBrowserCookies",
			profile.ErrNoCookies, envVars)
	}

	jar, err := auth.NewCookieJar("linkedin.com", cookies)
	if err != nil {
		return nil, fmt.Errorf("cookie jar creation failed: %w", err)
	}

	cfg.logger.InfoContext(ctx, "linkedin client created", "cookie_count", len(cookies))

	return &Client{
		httpClient: &http.Client{Jar: jar, Timeout: 3 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a LinkedIn profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	// Normalize URL
	if !strings.HasPrefix(urlStr, "http") {
		urlStr = "https://www.linkedin.com/in/" + urlStr
	}

	c.logger.InfoContext(ctx, "fetching linkedin profile", "url", urlStr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}

	setHeaders(req)

	body, err := cache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return parseProfile(body, urlStr)
}

// EnableDebug enables debug logging.
func (c *Client) EnableDebug() { c.debug = true }

func setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
}

func parseProfile(body []byte, profileURL string) (*profile.Profile, error) {
	content := string(body)
	targetID := extractPublicID(profileURL)

	prof := &profile.Profile{
		Platform:      platform,
		URL:           profileURL,
		Authenticated: true,
		Username:      targetID,
		Fields:        make(map[string]string),
	}

	// Extract profile data from embedded JSON in <code> blocks
	blocks := extractCodeBlocks(content)
	var fallbackData *profileData

	for _, code := range blocks {
		if !strings.Contains(code, `"publicIdentifier":`) {
			continue
		}

		var section string
		exact := false

		switch {
		case targetID != "" && strings.Contains(code, fmt.Sprintf(`"publicIdentifier":%q`, targetID)):
			exact = true
			section = extractProfileSection(code, targetID)
		case fallbackData == nil:
			section = code
		default:
			continue
		}

		data := extractProfileData(section)
		if data.name != "" {
			if exact {
				applyProfileData(prof, data, code)
				break
			}
			if fallbackData == nil {
				fallbackData = &data
			}
		}
	}

	if prof.Name == "" && fallbackData != nil {
		applyProfileData(prof, *fallbackData, content)
	}

	// Fallback to meta tags
	if prof.Name == "" {
		prof.Name = htmlutil.Title(content)
	}
	if prof.Bio == "" {
		prof.Bio = htmlutil.Description(content)
	}

	if prof.Name == "" {
		return nil, errors.New("failed to extract profile name")
	}

	// Verify we got the profile we requested (not logged-in user's feed)
	// Check if the extracted profile data contains the target ID
	if targetID != "" && prof.Username != "" {
		// The Username field should match our target (case-insensitive comparison)
		if !strings.EqualFold(prof.Username, targetID) {
			return nil, fmt.Errorf("profile not found (got %q instead of %q)", prof.Username, targetID)
		}
	}

	// Extract social links and websites
	prof.SocialLinks = htmlutil.SocialLinks(content)

	// Extract contact info URLs
	extractContactInfo(prof, content)

	// Filter out same-platform links (LinkedIn to LinkedIn)
	prof.SocialLinks = filterSamePlatformLinks(prof.SocialLinks)

	return prof, nil
}

type profileData struct {
	name     string
	headline string
	location string
	employer string
}

func extractProfileData(section string) profileData {
	first := extractJSONField(section, "firstName")
	last := extractJSONField(section, "lastName")

	data := profileData{
		headline: unescapeJSON(extractJSONField(section, "headline")),
	}

	if first != "" {
		data.name = unescapeJSON(first)
		if last != "" {
			data.name += " " + unescapeJSON(last)
		}
	}

	if loc := extractJSONField(section, "geoLocationName"); loc != "" {
		data.location = unescapeJSON(loc)
	}

	// Try multiple patterns for employer - check experience/positions first
	// Look for current position by finding entityUrn with "company"
	companyURNPattern := regexp.MustCompile(`"entityUrn"\s*:\s*"[^"]*company[^"]*"[^}]*"name"\s*:\s*"([^"]+)"`)
	if m := companyURNPattern.FindStringSubmatch(section); len(m) > 1 {
		data.employer = unescapeJSON(m[1])
	} else if company := extractJSONField(section, "companyName"); company != "" {
		data.employer = unescapeJSON(company)
	} else if company := extractJSONField(section, "company"); company != "" {
		data.employer = unescapeJSON(company)
	} else if title := extractJSONField(section, "title"); title != "" {
		// Sometimes title contains "Position at Company"
		if parsed := parseCompanyFromHeadline(unescapeJSON(title)); parsed != "" {
			data.employer = parsed
		}
	}

	return data
}

func applyProfileData(p *profile.Profile, data profileData, fullContent string) {
	p.Name = data.name
	p.Bio = data.headline
	p.Location = data.location

	if data.employer != "" {
		p.Fields["employer"] = data.employer
	} else if data.headline != "" {
		if company := parseCompanyFromHeadline(data.headline); company != "" {
			p.Fields["employer"] = company
		}
	}

	if p.Location == "" {
		// Look for geo entity with defaultLocalizedName
		re := regexp.MustCompile(`"defaultLocalizedName":"([^"]+)"`)
		if m := re.FindStringSubmatch(fullContent); len(m) > 1 {
			p.Location = unescapeJSON(m[1])
		}
	}
}

func extractPublicID(urlStr string) string {
	re := regexp.MustCompile(`/in/([^/]+)`)
	if m := re.FindStringSubmatch(urlStr); len(m) > 1 {
		slug := m[1]
		if strings.Contains(slug, "%") {
			if decoded, err := url.QueryUnescape(slug); err == nil {
				return decoded
			}
		}
		return slug
	}
	return ""
}

func extractCodeBlocks(s string) []string {
	re := regexp.MustCompile(`(?s)<code[^>]*>(.*?)</code>`)
	matches := re.FindAllStringSubmatch(s, -1)

	var blocks []string
	for _, m := range matches {
		if len(m) > 1 {
			blocks = append(blocks, html.UnescapeString(m[1]))
		}
	}
	return blocks
}

func extractJSONField(s, field string) string {
	// Try quoted field name with colon and value
	re := regexp.MustCompile(fmt.Sprintf(`%q\s*:\s*"([^"]*)"`, field))
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	// Try without quotes on field name
	re2 := regexp.MustCompile(fmt.Sprintf(`%s\s*:\s*"([^"]*)"`, field))
	if m := re2.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	return ""
}

func extractProfileSection(s, id string) string {
	search := fmt.Sprintf(`"publicIdentifier":%q`, id)
	idx := strings.Index(s, search)
	if idx == -1 {
		return s
	}
	start := max(0, idx-5000)
	end := min(len(s), idx+5000)
	return s[start:end]
}

func parseCompanyFromHeadline(headline string) string {
	var company string

	// Try patterns in order of specificity
	// "Position at Company" or "Position @ Company"
	if idx := strings.Index(headline, " at "); idx != -1 {
		company = headline[idx+4:]
	} else if idx := strings.Index(headline, " @ "); idx != -1 {
		company = headline[idx+3:]
	} else if idx := strings.Index(headline, "@"); idx != -1 {
		// Handle "@Company" without space (e.g., "Engineering @Akuity")
		company = headline[idx+1:]
	} else if parts := strings.SplitN(headline, ", ", 2); len(parts) == 2 {
		company = parts[1]
	} else {
		return ""
	}

	// Clean: trim whitespace and remove text after delimiters
	company = strings.TrimSpace(company)
	if idx := strings.IndexAny(company, ",;|"); idx != -1 {
		company = strings.TrimSpace(company[:idx])
	}
	return company
}

func unescapeJSON(s string) string {
	var unescaped string
	if err := json.Unmarshal([]byte(`"`+s+`"`), &unescaped); err != nil {
		return s
	}
	return unescaped
}

func extractContactInfo(p *profile.Profile, content string) {
	// Look for website/contact info in the profile
	// LinkedIn often has these in contact-info section or as part of profile data
	re := regexp.MustCompile(`"website":\s*"([^"]+)"`)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		website := unescapeJSON(matches[1])
		if website != "" && !strings.Contains(website, "linkedin.com") {
			p.Website = website
			p.Fields["website"] = website
		}
	}

	// Also look for URLs in the "websites" array
	websitesRe := regexp.MustCompile(`"websites":\s*\[([^\]]+)\]`)
	if matches := websitesRe.FindStringSubmatch(content); len(matches) > 1 {
		// Extract URLs from the array
		urlRe := regexp.MustCompile(`"url":\s*"([^"]+)"`)
		urlMatches := urlRe.FindAllStringSubmatch(matches[1], -1)
		for _, urlMatch := range urlMatches {
			if len(urlMatch) > 1 {
				website := unescapeJSON(urlMatch[1])
				if website != "" && !strings.Contains(website, "linkedin.com") {
					if p.Website == "" {
						p.Website = website
					}
					p.SocialLinks = append(p.SocialLinks, website)
				}
			}
		}
	}
}

func filterSamePlatformLinks(links []string) []string {
	var filtered []string
	for _, link := range links {
		// Skip LinkedIn URLs
		if !Match(link) {
			filtered = append(filtered, link)
		}
	}
	return filtered
}
