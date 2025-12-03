// Package linkedin fetches LinkedIn user profile data using authenticated session cookies.
package linkedin

import (
	"bytes"
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

	"github.com/codeGROOVE-dev/sociopath/pkg/auth"
	"github.com/codeGROOVE-dev/sociopath/pkg/cache"
	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "linkedin"

// linkedInBaseURL is the parsed base URL for LinkedIn.
// This is a compile-time constant that cannot fail to parse.
var linkedInBaseURL, _ = url.Parse("https://www.linkedin.com") //nolint:errcheck // constant URL cannot fail

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
		httpClient: &http.Client{
			Jar:     jar,
			Timeout: 3 * time.Second,
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= 1 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
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

	// Extract username from URL for API calls
	username := extractPublicID(urlStr)

	// Try to extract the target profile's member URN from the HTML
	// IMPORTANT: The HTML contains URNs for both logged-in user and viewed profile
	// We must extract the URN for the TARGET profile, not the logged-in user
	memberURN := extractTargetMemberURN(body, username)
	c.logger.DebugContext(ctx, "extracted for API call", "username", username, "memberURN", memberURN)

	// PRIMARY: Use Voyager API to get profile data (avoids logged-in user data contamination)
	// The HTML often contains the logged-in user's data mixed with viewed profile data
	var prof *profile.Profile
	if memberURN != "" {
		prof = c.fetchProfileFromAPI(ctx, memberURN, urlStr, username)
	}

	// FALLBACK: Parse HTML only if API failed
	if prof == nil {
		var parseErr error
		prof, parseErr = parseProfile(body, urlStr)
		if parseErr != nil {
			c.logger.DebugContext(ctx, "linkedin parse failed",
				"url", urlStr,
				"error", parseErr,
				"response_size", len(body),
			)
			return prof, parseErr
		}
	}

	// Ensure we have experience data
	if prof.Fields["employer"] == "" || prof.Fields["title"] == "" {
		if memberURN != "" {
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

	// Ensure we have location
	if prof.Location == "" && memberURN != "" {
		loc := c.fetchLocationFromAPI(ctx, memberURN)
		if loc != "" {
			prof.Location = loc
			c.logger.DebugContext(ctx, "location found via API", "location", loc)
		}
	}

	// Extract social links from HTML (API doesn't provide these)
	prof.SocialLinks = htmlutil.SocialLinks(string(body))
	extractContactInfo(prof, string(body))
	prof.SocialLinks = filterSamePlatformLinks(prof.SocialLinks)

	return prof, nil
}

// EnableDebug enables debug logging.
func (c *Client) EnableDebug() { c.debug = true }

// fetchProfileFromAPI fetches the profile data from the LinkedIn Voyager API.
// This is the primary method for getting profile data as it avoids logged-in user data contamination.
// Uses the /identity/profiles/{publicIdentifier} endpoint which returns profile by username.
func (c *Client) fetchProfileFromAPI(ctx context.Context, _, profileURL, username string) *profile.Profile {
	if username == "" {
		c.logger.DebugContext(ctx, "no username for profile API call")
		return nil
	}

	if err := c.ensureSessionCookies(ctx); err != nil {
		c.logger.DebugContext(ctx, "failed to get session cookies for profile", "error", err)
		return nil
	}

	// Use the identity/profiles endpoint which takes publicIdentifier (username) directly
	// This avoids the problem of extracting wrong URN from HTML
	apiURL := fmt.Sprintf("https://www.linkedin.com/voyager/api/identity/profiles/%s", url.PathEscape(username))

	c.logger.DebugContext(ctx, "fetching profile from voyager api", "url", apiURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		c.logger.DebugContext(ctx, "profile api request creation failed", "error", err)
		return nil
	}

	setVoyagerHeaders(req, c.httpClient, c.logger)
	req.Header.Set("Accept", "application/vnd.linkedin.normalized+json+2.1")

	body, err := cache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		c.logger.DebugContext(ctx, "profile api request failed", "error", err)
		return nil
	}

	c.logger.DebugContext(ctx, "profile api response", "bodySize", len(body))

	return extractProfileFromIdentityAPI(body, profileURL, username, c.logger)
}

// extractProfileFromIdentityAPI extracts profile data from the /identity/profiles/ API response.
// This endpoint returns profile data with fields like firstName, lastName, headline, geoLocationName.
func extractProfileFromIdentityAPI(body []byte, profileURL, username string, logger *slog.Logger) *profile.Profile {
	prof := &profile.Profile{
		Platform:      platform,
		URL:           profileURL,
		Authenticated: true,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// The identity/profiles API returns JSON with direct fields:
	// firstName, lastName, headline, geoLocationName, industryName, etc.

	// Extract firstName and lastName
	firstName := extractJSONField(string(body), "firstName")
	lastName := extractJSONField(string(body), "lastName")
	if firstName != "" {
		prof.Name = unescapeJSON(firstName)
		if lastName != "" {
			prof.Name += " " + unescapeJSON(lastName)
		}
		logger.Debug("extracted name from identity API", "name", prof.Name)
	}

	// Extract headline (bio)
	if headline := extractJSONField(string(body), "headline"); headline != "" {
		prof.Bio = unescapeJSON(headline)
		logger.Debug("extracted headline from identity API", "headline", prof.Bio)
	}

	// Extract location
	if loc := extractJSONField(string(body), "geoLocationName"); loc != "" {
		prof.Location = unescapeJSON(loc)
		logger.Debug("extracted location from identity API", "location", prof.Location)
	}

	// Extract pronouns
	pronounRe := regexp.MustCompile(`"standardizedPronoun"\s*:\s*"(HE_HIM|SHE_HER|THEY_THEM)"`)
	if m := pronounRe.FindSubmatch(body); len(m) > 1 {
		pronouns := convertStandardizedPronoun(string(m[1]))
		if pronouns != "" {
			prof.Fields["pronouns"] = pronouns
			logger.Debug("extracted pronouns from identity API", "pronouns", pronouns)
		}
	}

	// If no name found, return nil to fall back to HTML parsing
	if prof.Name == "" {
		logger.Debug("no name found in identity API response")
		return nil
	}

	return prof
}

// extractProfileFromGraphQLResponse extracts profile data from the TOP_CARD GraphQL response.
// This is a fallback method if the identity/profiles endpoint fails.
func extractProfileFromGraphQLResponse(body []byte, profileURL, username string, logger *slog.Logger) *profile.Profile {
	prof := &profile.Profile{
		Platform:      platform,
		URL:           profileURL,
		Authenticated: true,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// The TOP_CARD response contains the profile name and headline in "text" fields
	// Structure: elements containing titleV2 with text for name, subtitleV2 for headline
	// Look for patterns like: "titleV2":{"text":{"text":"Stephen Fox Jr."

	// Extract name from titleV2
	titleRe := regexp.MustCompile(`"titleV2"\s*:\s*\{[^}]*"text"\s*:\s*\{[^}]*"text"\s*:\s*"([^"]+)"`)
	if m := titleRe.FindSubmatch(body); len(m) > 1 {
		prof.Name = strings.TrimSpace(string(m[1]))
		logger.Debug("extracted name from titleV2", "name", prof.Name)
	} else {
		logger.Debug("titleV2 pattern not found")
	}

	// Extract headline/bio from subtitleV2
	subtitleRe := regexp.MustCompile(`"subtitleV2"\s*:\s*\{[^}]*"text"\s*:\s*\{[^}]*"text"\s*:\s*"([^"]+)"`)
	if m := subtitleRe.FindSubmatch(body); len(m) > 1 {
		prof.Bio = strings.TrimSpace(string(m[1]))
		logger.Debug("extracted bio from subtitleV2", "bio", prof.Bio)
	} else {
		logger.Debug("subtitleV2 pattern not found")
	}

	// Extract location
	loc := extractLocationFromGraphQLResponse(body)
	if loc != "" {
		prof.Location = loc
	}

	// Extract pronouns - look for standardizedPronoun
	pronounRe := regexp.MustCompile(`"standardizedPronoun"\s*:\s*"(HE_HIM|SHE_HER|THEY_THEM)"`)
	if m := pronounRe.FindSubmatch(body); len(m) > 1 {
		pronouns := convertStandardizedPronoun(string(m[1]))
		if pronouns != "" {
			prof.Fields["pronouns"] = pronouns
		}
	}

	// If no name found, return nil to fall back to HTML parsing
	if prof.Name == "" {
		return nil
	}

	return prof
}

// extractTargetMemberURN extracts the member URN for the TARGET profile from HTML.
// This is critical because LinkedIn pages contain URNs for both the logged-in user
// and the profile being viewed. We need to find the URN that belongs to the target.
func extractTargetMemberURN(body []byte, targetUsername string) string {
	// Strategy 1: Look for URN associated with the target username in the URL
	// Pattern: fsd_profileCard with publicIdentifier matching target
	if targetUsername != "" {
		// Look for the pattern that ties publicIdentifier to a member URN
		// Example: "publicIdentifier":"stephen-fox-jr"... nearby "fsd_profile:ACoA..."
		pattern := fmt.Sprintf(`"publicIdentifier"\s*:\s*"%s"[^}]*}[^{]*\{[^}]*fsd_profile:(ACoA[A-Za-z0-9_-]+)`, regexp.QuoteMeta(targetUsername))
		re := regexp.MustCompile(pattern)
		if m := re.FindSubmatch(body); len(m) > 1 {
			return string(m[1])
		}
	}

	// Strategy 2: Look for fsd_profileCard URN which is typically the viewed profile
	// Pattern: fsd_profileCard:(ACoA...,SECTION_TYPE
	cardRe := regexp.MustCompile(`fsd_profileCard:\((ACoA[A-Za-z0-9_-]+),`)
	if match := cardRe.FindSubmatch(body); len(match) > 1 {
		return string(match[1])
	}

	// Strategy 3: Look for profile URN in the page's data
	// The viewed profile's URN often appears in specific contexts
	profileRe := regexp.MustCompile(`fsd_profile:(ACoA[A-Za-z0-9_-]+)`)
	matches := profileRe.FindAllSubmatch(body, -1)

	// If we have multiple URNs, we need to identify which is the target
	// Usually the most frequently occurring one in certain contexts is the viewed profile
	if len(matches) > 0 {
		// Count occurrences of each URN
		urnCounts := make(map[string]int)
		for _, m := range matches {
			urn := string(m[1])
			urnCounts[urn]++
		}

		// Return the most common URN (likely the viewed profile)
		var maxURN string
		maxCount := 0
		for urn, count := range urnCounts {
			if count > maxCount {
				maxCount = count
				maxURN = urn
			}
		}
		if maxURN != "" {
			return maxURN
		}
	}

	// Last resort: any ACoA pattern
	re := regexp.MustCompile(`ACoA[A-Za-z0-9_-]+`)
	match := re.Find(body)
	if len(match) > 0 {
		return string(match)
	}

	return ""
}

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

	body, err := cache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		c.logger.DebugContext(ctx, "voyager api request failed", "error", err)
		return experienceData{}
	}

	c.logger.DebugContext(ctx, "response body", "url", apiURL, "body", string(body))

	exp := extractExperienceFromGraphQLResponse(body)
	c.logger.DebugContext(ctx, "voyager api response parsed", "title", exp.title, "employer", exp.employer, "bodySize", len(body))
	return exp
}

// fetchLocationFromAPI fetches the user's location from the LinkedIn Voyager API.
// This is used as a fallback when location isn't found in the HTML response.
func (c *Client) fetchLocationFromAPI(ctx context.Context, memberURN string) string {
	if err := c.ensureSessionCookies(ctx); err != nil {
		c.logger.DebugContext(ctx, "failed to get session cookies for location", "error", err)
		return ""
	}

	if memberURN == "" {
		return ""
	}

	// Use the profile components endpoint with TOP_CARD section to get location
	profileURN := url.QueryEscape(fmt.Sprintf("urn:li:fsd_profile:%s", memberURN))
	queryID := "voyagerIdentityDashProfileComponents.7af5d6f176f11583b382e37e5639e69e"
	baseURL := "https://www.linkedin.com/voyager/api/graphql"
	apiURL := fmt.Sprintf("%s?variables=(profileUrn:%s,sectionType:TOP_CARD)&queryId=%s&includeWebMetadata=true",
		baseURL, profileURN, queryID)

	c.logger.DebugContext(ctx, "fetching location from voyager api", "url", apiURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		c.logger.DebugContext(ctx, "location api request creation failed", "error", err)
		return ""
	}

	setVoyagerHeaders(req, c.httpClient, c.logger)
	req.Header.Set("Accept", "application/vnd.linkedin.normalized+json+2.1")

	body, err := cache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		c.logger.DebugContext(ctx, "location api request failed", "error", err)
		return ""
	}

	c.logger.DebugContext(ctx, "location api response", "bodySize", len(body))

	// Extract location from the response
	// Look for geoLocation or locationName patterns
	return extractLocationFromGraphQLResponse(body)
}

func extractLocationFromGraphQLResponse(body []byte) string {
	// Try multiple patterns for location extraction
	// Pattern 1: "geoLocationName":"Greater Boston"
	geoNameRe := regexp.MustCompile(`"geoLocationName"\s*:\s*"([^"]+)"`)
	if m := geoNameRe.FindSubmatch(body); len(m) > 1 {
		loc := strings.TrimSpace(string(m[1]))
		if loc != "" && loc != "null" {
			return loc
		}
	}

	// Pattern 2: "locationName":"Greater Boston"
	locNameRe := regexp.MustCompile(`"locationName"\s*:\s*"([^"]+)"`)
	if m := locNameRe.FindSubmatch(body); len(m) > 1 {
		loc := strings.TrimSpace(string(m[1]))
		if loc != "" && loc != "null" {
			return loc
		}
	}

	// Pattern 3: "defaultLocalizedName" in geo context (looking for longer locations)
	defaultLocRe := regexp.MustCompile(`"defaultLocalizedName"\s*:\s*"([^"]{10,})"`)
	if m := defaultLocRe.FindSubmatch(body); len(m) > 1 {
		loc := strings.TrimSpace(string(m[1]))
		// Filter out common non-location values
		if loc != "" && loc != "null" && !strings.Contains(strings.ToLower(loc), "linkedin") {
			return loc
		}
	}

	// Pattern 4: Look for geo object with text field
	geoTextRe := regexp.MustCompile(`"geo"[^}]*"text"\s*:\s*"([^"]+)"`)
	if m := geoTextRe.FindSubmatch(body); len(m) > 1 {
		loc := strings.TrimSpace(string(m[1]))
		if loc != "" && loc != "null" {
			return loc
		}
	}

	return ""
}

// ensureSessionCookies makes a request to LinkedIn to get session cookies (JSESSIONID).
func (c *Client) ensureSessionCookies(ctx context.Context) error {
	// Check if we already have JSESSIONID
	for _, cookie := range c.httpClient.Jar.Cookies(linkedInBaseURL) {
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

	// Use cache - the cookies will be set on first request, and subsequent
	// requests will hit cache (we already have the cookies in the jar)
	_, err = cache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return err
	}

	// Check if we got JSESSIONID
	for _, cookie := range c.httpClient.Jar.Cookies(linkedInBaseURL) {
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
		cookies := client.Jar.Cookies(linkedInBaseURL)
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

	// The GraphQL response has all text fields as sequential "text":"value" pairs
	// For the current position, the order is:
	// 1. Duration: "Oct 2021 - Present · 4 yrs 3 mos"
	// 2. Title: "Undisclosed" (or actual job title)
	// 3. Company: "/tmp/x · Full-time" (company name + employment type)
	//
	// We need to find the title and company that belong together by looking
	// at the sequence of text fields after the duration pattern.

	// Extract all "text":"value" pairs in order
	textRe := regexp.MustCompile(`"text":"([^"]+)"`)
	matches := textRe.FindAllSubmatch(body, -1)

	// Find the first occurrence of a duration pattern (indicates start of first experience)
	// Duration patterns look like: "Oct 2021 - Present · 4 yrs" or "Jan 2008 - Dec 2019 · 12 yrs"
	durationRe := regexp.MustCompile(`^[A-Z][a-z]{2} \d{4} - `)

	for i, m := range matches {
		text := string(m[1])
		// Skip common non-content values
		if text == "USER_LOCALE" || text == "" {
			continue
		}

		// If we find a duration pattern, the next entries should be title and company
		if durationRe.MatchString(text) {
			// Look at the next two text fields for title and company
			if i+1 < len(matches) {
				title := string(matches[i+1][1])
				if title != "" && title != "USER_LOCALE" && !durationRe.MatchString(title) {
					result.title = title
				}
			}
			if i+2 < len(matches) {
				companyInfo := string(matches[i+2][1])
				if companyInfo != "" && companyInfo != "USER_LOCALE" && !durationRe.MatchString(companyInfo) {
					// Company format is "Company · Employment Type" - extract just the company
					parts := strings.Split(companyInfo, " · ")
					if len(parts) > 0 && parts[0] != "" {
						result.employer = parts[0]
					}
				}
			}
			// Found the first experience entry, we're done
			if result.title != "" {
				break
			}
		}
	}

	// Fallback: if no duration pattern found, try titleV2 structure
	if result.title == "" {
		titleV2Re := regexp.MustCompile(`"titleV2":\{[^}]*"text":\{[^}]*"text":"([^"]+)"`)
		if m := titleV2Re.FindSubmatch(body); len(m) > 1 {
			title := strings.TrimSpace(string(m[1]))
			if title != "" && title != "USER_LOCALE" {
				result.title = title
			}
		}
	}

	// Fallback for employer: company logo accessibility text (first one should be current employer)
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
	// "Greater Boston" is 14 chars, so we use 10+ as minimum to filter out country-only entries
	if p.Location == "" {
		// Try defaultLocalizedNameWithoutCountryName first (more specific)
		re := regexp.MustCompile(`"defaultLocalizedNameWithoutCountryName"\s*:\s*"([^"]{5,})"`)
		if m := re.FindStringSubmatch(fullContent); len(m) > 1 {
			p.Location = unescapeJSON(m[1])
		}
	}
	if p.Location == "" {
		re := regexp.MustCompile(`"defaultLocalizedName"\s*:\s*"([^"]{10,})"`)
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
