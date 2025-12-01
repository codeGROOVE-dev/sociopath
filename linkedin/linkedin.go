// Package linkedin fetches LinkedIn user profile data using authenticated session cookies.
package linkedin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
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

	// Use validator to avoid caching empty SPA shell pages from LinkedIn
	// Shell pages have <title>LinkedIn</title> without profile data embedded
	body, err := cache.FetchURLWithValidator(ctx, c.cache, c.httpClient, req, c.logger, isValidProfilePage)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	prof, parseErr := parseProfile(body, urlStr)
	if parseErr != nil {
		// Log additional context for debugging
		c.logger.DebugContext(ctx, "linkedin parse failed",
			"url", urlStr,
			"error", parseErr,
			"response_size", len(body),
		)
		return prof, parseErr
	}

	// If no employer found from HTML parsing, try the Voyager API
	c.logger.DebugContext(ctx, "checking employer", "employer", prof.Fields["employer"])
	if prof.Fields["employer"] == "" || prof.Fields["title"] == "" {
		username := extractPublicID(urlStr)
		memberURN := extractMemberURN(body)
		c.logger.DebugContext(ctx, "extracted for API call", "username", username, "memberURN", memberURN)
		if username != "" || memberURN != "" {
			exp := c.fetchExperienceFromAPI(ctx, username, memberURN)
			if exp.employer != "" && prof.Fields["employer"] == "" {
				prof.Fields["employer"] = exp.employer
				c.logger.DebugContext(ctx, "employer found via API", "employer", exp.employer)
			}
			if exp.title != "" {
				prof.Fields["title"] = exp.title
				c.logger.DebugContext(ctx, "title found via API", "title", exp.title)
			}
		}
	}

	return prof, parseErr
}

// EnableDebug enables debug logging.
func (c *Client) EnableDebug() { c.debug = true }

// fetchExperienceFromAPI calls the LinkedIn Voyager API to get profile experience data.
func (c *Client) fetchExperienceFromAPI(ctx context.Context, _ string, memberURN string) experienceData {
	// First, make a request to LinkedIn to get session cookies (JSESSIONID)
	// This is necessary because JSESSIONID is set as a response cookie, not stored persistently
	if err := c.ensureSessionCookies(ctx); err != nil {
		c.logger.DebugContext(ctx, "failed to get session cookies", "error", err)
		return experienceData{}
	}

	if memberURN == "" {
		c.logger.DebugContext(ctx, "no member URN available for API call")
		return experienceData{}
	}

	// Use GraphQL endpoint to get experience data
	profileURN := url.QueryEscape(fmt.Sprintf("urn:li:fsd_profile:%s", memberURN))
	queryID := "voyagerIdentityDashProfileComponents.7af5d6f176f11583b382e37e5639e69e"
	baseURL := "https://www.linkedin.com/voyager/api/graphql"
	apiURL := fmt.Sprintf("%s?variables=(profileUrn:%s,sectionType:experience)&queryId=%s&includeWebMetadata=true",
		baseURL, profileURN, queryID)
	c.logger.DebugContext(ctx, "calling voyager api", "url", apiURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		c.logger.DebugContext(ctx, "voyager api request creation failed", "error", err)
		return experienceData{}
	}

	setVoyagerHeaders(req, c.httpClient, c.logger)
	req.Header.Set("Accept", "application/vnd.linkedin.normalized+json+2.1")

	// Don't use cache for API calls - they need fresh CSRF tokens
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.DebugContext(ctx, "voyager api request failed", "error", err)
		return experienceData{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.logger.DebugContext(ctx, "voyager api request failed", "status", resp.StatusCode)
		return experienceData{}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.DebugContext(ctx, "voyager api body read failed", "error", err)
		return experienceData{}
	}

	c.logger.DebugContext(ctx, "response body", "url", apiURL, "body", string(body))

	exp := extractExperienceFromGraphQLResponse(body)
	c.logger.DebugContext(ctx, "voyager api response parsed", "title", exp.title, "employer", exp.employer, "bodySize", len(body))
	return exp
}

// ensureSessionCookies makes a request to LinkedIn to get session cookies (JSESSIONID).
func (c *Client) ensureSessionCookies(ctx context.Context) error {
	// Check if we already have JSESSIONID
	u, _ := url.Parse("https://www.linkedin.com")
	for _, cookie := range c.httpClient.Jar.Cookies(u) {
		if cookie.Name == "JSESSIONID" {
			c.logger.DebugContext(ctx, "JSESSIONID already present")
			return nil
		}
	}

	// Make a request to get session cookies
	c.logger.DebugContext(ctx, "fetching session cookies")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.linkedin.com/feed/", http.NoBody)
	if err != nil {
		return err
	}
	setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body) // drain body

	// Check if we got JSESSIONID
	for _, cookie := range c.httpClient.Jar.Cookies(u) {
		if cookie.Name == "JSESSIONID" {
			c.logger.DebugContext(ctx, "got JSESSIONID from response")
			return nil
		}
	}

	c.logger.DebugContext(ctx, "JSESSIONID not found in response cookies")
	return nil
}

func setVoyagerHeaders(req *http.Request, client *http.Client, logger *slog.Logger) {
	// Chrome user agent - split into parts to avoid long line
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
	req.Header.Set("User-Agent", ua)
	// Note: don't set Accept header - LinkedIn API is picky about it
	req.Header.Set("Accept-Language", "en-AU,en-GB;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("X-Li-Lang", "en_US")
	req.Header.Set("X-Restli-Protocol-Version", "2.0.0")

	// Extract CSRF token from JSESSIONID cookie
	if client.Jar != nil {
		u, _ := url.Parse("https://www.linkedin.com")
		cookies := client.Jar.Cookies(u)
		logger.Debug("voyager api cookies available", "count", len(cookies))
		for _, cookie := range cookies {
			if cookie.Name == "JSESSIONID" {
				// Strip quotes from the value
				csrfToken := strings.Trim(cookie.Value, `"`)
				req.Header.Set("Csrf-Token", csrfToken)
				logger.Debug("csrf token set", "token", csrfToken[:min(len(csrfToken), 20)]+"...")
				break
			}
		}
	}
}

// isValidProfilePage checks if a LinkedIn response contains actual profile data.
// LinkedIn sometimes returns SPA shell pages with <title>LinkedIn</title> but no profile data.
// These shell pages should NOT be cached as they require JavaScript to load content.
func isValidProfilePage(body []byte) bool {
	// Shell pages have generic <title>LinkedIn</title>
	// Valid profile pages have <title>Name | LinkedIn</title> or contain embedded JSON data
	hasGenericTitle := bytes.Contains(body, []byte("<title>LinkedIn</title>"))
	hasProfileData := bytes.Contains(body, []byte("fsd_profile:")) ||
		bytes.Contains(body, []byte(`"publicIdentifier"`)) ||
		bytes.Contains(body, []byte(`"firstName"`))

	// Valid if it has profile data OR doesn't have the generic shell title
	return hasProfileData || !hasGenericTitle
}

// extractMemberURN extracts the encoded member ID from the profile HTML response.
// LinkedIn profile pages contain encoded IDs like "ACoAAABI9AMB..." which are used for API calls.
// Important: The HTML contains URNs for both the logged-in user AND the profile being viewed.
// We need to find the one associated with the profile, not the logged-in user.
func extractMemberURN(body []byte) string {
	// FIRST: look for profileCard URN which is tied to the viewed profile (not the logged-in user)
	// Pattern: fsd_profileCard:(ACoA...,EXPERIENCE or fsd_profileCard:(ACoA...,EDUCATION
	// This pattern only appears for the profile being viewed, not the logged-in user
	cardRe := regexp.MustCompile(`fsd_profileCard:\((ACoA[A-Za-z0-9_-]+),`)
	if match := cardRe.FindSubmatch(body); len(match) > 1 {
		return string(match[1])
	}

	// Fallback: look for the profile URN - but this may match logged-in user
	// Pattern: "*elements":["urn:li:fsd_profile:ACoA..."]
	profileRe := regexp.MustCompile(`fsd_profile:(ACoA[A-Za-z0-9_-]+)`)
	if match := profileRe.FindSubmatch(body); len(match) > 1 {
		return string(match[1])
	}

	// Last resort: any ACoA pattern (may pick up wrong user)
	re := regexp.MustCompile(`ACoA[A-Za-z0-9_-]+`)
	match := re.Find(body)
	if len(match) > 0 {
		return string(match)
	}
	return ""
}

// experienceData holds extracted job title and employer from the experience section.
type experienceData struct {
	title    string
	employer string
}

func extractExperienceFromGraphQLResponse(body []byte) experienceData {
	result := experienceData{}

	// The GraphQL response has a complex nested structure
	// We look for job title in titleV2 and company in subtitle
	// Structure: data.elements[].components.entityComponent.titleV2.text.text = "Job Title"
	// Structure: data.elements[].components.entityComponent.subtitle.text = "Company · Full-time · Duration"

	// Try JSON parsing first (more reliable)
	var data struct {
		Data struct {
			IdentityDashProfileComponentsBySectionType struct {
				Elements []struct {
					Components struct {
						EntityComponent struct {
							TitleV2 struct {
								Text struct {
									Text string `json:"text"`
								} `json:"text"`
							} `json:"titleV2"`
							Subtitle struct {
								Text string `json:"text"`
							} `json:"subtitle"`
						} `json:"entityComponent"`
					} `json:"components"`
				} `json:"elements"`
			} `json:"identityDashProfileComponentsBySectionType"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &data); err == nil {
		elements := data.Data.IdentityDashProfileComponentsBySectionType.Elements
		if len(elements) > 0 {
			// The first element is usually the current position
			elem := elements[0].Components.EntityComponent

			// Extract job title from titleV2
			if title := elem.TitleV2.Text.Text; title != "" && title != "USER_LOCALE" {
				result.title = title
			}

			// Extract employer from subtitle (format: "Company · Employment Type · Duration")
			if subtitle := elem.Subtitle.Text; subtitle != "" {
				parts := strings.Split(subtitle, " · ")
				if len(parts) > 0 && parts[0] != "" && parts[0] != "USER_LOCALE" {
					result.employer = parts[0]
				}
			}
		}
	}

	// Fallback to regex if JSON parsing didn't find the data
	if result.title == "" {
		titleRe := regexp.MustCompile(`"titleV2":\{[^}]*"text":\{[^}]*"text":"([^"]+)"`)
		if m := titleRe.FindSubmatch(body); len(m) > 1 {
			title := strings.TrimSpace(string(m[1]))
			if title != "" && title != "USER_LOCALE" {
				result.title = title
			}
		}
	}

	if result.employer == "" {
		// Try subtitle regex pattern
		subtitleRe := regexp.MustCompile(`"subtitle":\{[^}]*"text":\{[^}]*"text":"([^"·]+)\s*·`)
		if m := subtitleRe.FindSubmatch(body); len(m) > 1 {
			employer := strings.TrimSpace(string(m[1]))
			if employer != "" && employer != "USER_LOCALE" {
				result.employer = employer
			}
		}
	}

	// Fallback for employer: company logo accessibility text
	if result.employer == "" {
		logoRe := regexp.MustCompile(`"accessibilityText":"([^"]+) logo"`)
		if m := logoRe.FindSubmatch(body); len(m) > 1 {
			result.employer = strings.TrimSpace(string(m[1]))
		}
	}

	return result
}

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

	// Detect error pages before attempting to parse
	// Check title first - most reliable indicator
	titleStart := strings.Index(content, "<title>")
	titleEnd := strings.Index(content, "</title>")
	if titleStart >= 0 && titleEnd > titleStart {
		title := strings.ToLower(content[titleStart+7 : titleEnd])
		titleErrorPatterns := []string{
			"page not found",
			"404",
			"member not found",
			"profile not found",
		}
		for _, pattern := range titleErrorPatterns {
			if strings.Contains(title, pattern) {
				return nil, fmt.Errorf("profile not found (error in title: %q)", pattern)
			}
		}
	}

	// Check for other error indicators in the body
	lowerContent := strings.ToLower(content)
	bodyErrorPatterns := []string{
		"this profile is not available",
		"account has been restricted",
		"page doesn't exist",
		"member you are trying to view",
	}
	for _, pattern := range bodyErrorPatterns {
		if strings.Contains(lowerContent, pattern) {
			return nil, fmt.Errorf("profile not found (error page detected: %q in response)", pattern)
		}
	}

	targetID := extractPublicID(profileURL)

	prof := &profile.Profile{
		Platform:      platform,
		URL:           profileURL,
		Authenticated: true,
		Username:      "", // Will be extracted from HTML
		Fields:        make(map[string]string),
	}

	// Extract profile data from embedded JSON in <code> blocks
	blocks := extractCodeBlocks(content)
	var fallbackData *profileData
	var actualUsername string

	// Concatenate all blocks for location/pronoun extraction
	allBlocksContent := strings.Join(blocks, "\n")

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
			actualUsername = targetID
		case fallbackData == nil:
			section = code
			// Extract the actual publicIdentifier from this section
			if extracted := extractPublicIdentifier(code); extracted != "" {
				actualUsername = extracted
			}
		default:
			continue
		}

		data := extractProfileData(section)
		if data.name != "" {
			if exact {
				prof.Username = actualUsername
				applyProfileData(prof, data, allBlocksContent)
				break
			}
			if fallbackData == nil {
				fallbackData = &data
			}
		}
	}

	if prof.Name == "" && fallbackData != nil {
		prof.Username = actualUsername
		applyProfileData(prof, *fallbackData, allBlocksContent)
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

	// Check if LinkedIn redirected to a different profile
	// This can happen when:
	// 1. Old profile URL redirects to new canonical URL (OK - same person)
	// 2. Non-existent profile redirects to logged-in user (BAD - different person)
	// We can't distinguish these cases at parse time, so return both the requested
	// URL and actual username. The caller (guess logic) can verify if needed.
	// For vouched URLs from trusted sources, the redirect is acceptable.
	if targetID != "" && prof.Username != "" && !strings.EqualFold(prof.Username, targetID) {
		// Update URL to canonical form to help callers detect duplicates
		prof.URL = "https://www.linkedin.com/in/" + prof.Username
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

	data := profileData{}

	// Try 'headline' first (from Profile object), then 'occupation' (from MiniProfile object)
	if headline := extractJSONField(section, "headline"); headline != "" {
		data.headline = unescapeJSON(headline)
	} else if occupation := extractJSONField(section, "occupation"); occupation != "" {
		data.headline = unescapeJSON(occupation)
	}

	if first != "" {
		data.name = unescapeJSON(first)
		if last != "" {
			data.name += " " + unescapeJSON(last)
		}
	}

	// Try 'geoLocationName' (old format) or look for geoLocation reference
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

	// Extract pronouns - look for actual pronoun values (HE_HIM, SHE_HER, THEY_THEM), not schema definitions
	re := regexp.MustCompile(`"standardizedPronoun"\s*:\s*"(HE_HIM|SHE_HER|THEY_THEM)"`)
	if m := re.FindStringSubmatch(fullContent); len(m) > 1 {
		pronouns := convertStandardizedPronoun(m[1])
		if pronouns != "" {
			p.Fields["pronouns"] = pronouns
		}
	}

	// Location extraction - prefer longer location names (city, state, country) over short ones (just country)
	if p.Location == "" {
		re := regexp.MustCompile(`"defaultLocalizedName"\s*:\s*"([^"]{15,})"`)
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

// extractPublicIdentifier extracts the first publicIdentifier value from JSON content.
func extractPublicIdentifier(content string) string {
	// Look for "publicIdentifier":"value"
	re := regexp.MustCompile(`"publicIdentifier"\s*:\s*"([^"]+)"`)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		return matches[1]
	}
	return ""
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
	} else {
		// Don't try to extract company from comma-separated lists
		// Headlines like "P2P, Rust, FP, databases" are skill lists, not "Title, Company"
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

func convertStandardizedPronoun(code string) string {
	switch code {
	case "HE_HIM":
		return "He/Him"
	case "SHE_HER":
		return "She/Her"
	case "THEY_THEM":
		return "They/Them"
	default:
		return ""
	}
}
