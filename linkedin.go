// Package linkedin fetches LinkedIn user profile data using authenticated session cookies.
package linkedin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/browserutils/kooky"
	_ "github.com/browserutils/kooky/browser/all" // Import all browser cookie stores
	"github.com/browserutils/kooky/browser/firefox"
)

// Profile represents a LinkedIn user profile.
type Profile struct {
	Name            string
	Headline        string
	CurrentEmployer string
	ProfileURL      string
	Location        string
	About           string
}

// Client handles LinkedIn API requests with authenticated cookies.
type Client struct {
	httpClient *http.Client
	logger     *slog.Logger
	debug      bool
}

// New creates a LinkedIn client using Firefox cookies by default.
// If environment variables are set, they take precedence over browser cookies.
// Supported env vars: LINKEDIN_LI_AT, LINKEDIN_JSESSIONID, LINKEDIN_LIDC, LINKEDIN_BCOOKIE.
func New(ctx context.Context) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("cookie jar creation failed: %w", err)
	}

	u, err := url.Parse("https://www.linkedin.com")
	if err != nil {
		return nil, fmt.Errorf("URL parsing failed: %w", err)
	}
	var cookies []*http.Cookie

	// Try environment variables first
	env := cookiesFromEnv()
	if len(env) > 0 {
		cookies = env
		slog.InfoContext(ctx, "using cookies from environment variables", "count", len(env))
	} else {
		// Fall back to browser cookies
		var kookies []*kooky.Cookie
		var err error

		// First try Firefox Developer Edition and other Firefox profiles directly
		ff := tryFirefoxProfiles(ctx)
		if len(ff) > 0 {
			kookies = ff
		} else {
			// Fall back to kooky's automatic detection
			kookies, err = kooky.ReadCookies(ctx, kooky.Valid, kooky.DomainHasSuffix("linkedin.com"))
			if err != nil {
				return nil, fmt.Errorf(
					"failed to read browser cookies: %w\n\n"+
						"To use environment variables instead, set:\n"+
						"  export LINKEDIN_LI_AT=\"your-li_at-value\"\n"+
						"  export LINKEDIN_JSESSIONID=\"your-jsessionid-value\"\n"+
						"  export LINKEDIN_LIDC=\"your-lidc-value\"", err)
			}
		}

		if len(kookies) == 0 {
			return nil, errors.New(
				"no LinkedIn cookies found in browser\n\n" +
					"Please either:\n" +
					"  1. Log in to LinkedIn in a supported browser (Chrome, Firefox, Edge, Safari)\n" +
					"  2. Set cookies via environment variables:\n" +
					"     export LINKEDIN_LI_AT=\"your-li_at-value\"\n" +
					"     export LINKEDIN_JSESSIONID=\"your-jsessionid-value\"\n" +
					"     export LINKEDIN_LIDC=\"your-lidc-value\"")
		}

		// Filter to only essential cookies
		essential := filterEssentialCookies(kookies)

		// Log all cookie names for debugging
		names := make([]string, len(kookies))
		for i, c := range kookies {
			names[i] = c.Name
		}

		slog.InfoContext(ctx, "found LinkedIn cookies",
			"total", len(kookies),
			"essential", len(essential),
			"all_names", names)

		for _, c := range essential {
			cookies = append(cookies, &http.Cookie{
				Name:     c.Name,
				Value:    c.Value,
				Domain:   c.Domain,
				Path:     c.Path,
				Expires:  c.Expires,
				Secure:   c.Secure,
				HttpOnly: c.HttpOnly,
			})
		}
	}

	jar.SetCookies(u, cookies)

	client := &Client{
		httpClient: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
		},
		logger: slog.Default(),
	}

	return client, nil
}

// NewWithCookies creates a LinkedIn client with explicit cookie values.
// This is useful for testing different cookie combinations.
func NewWithCookies(ctx context.Context, cookies map[string]string) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("cookie jar creation failed: %w", err)
	}

	u, err := url.Parse("https://www.linkedin.com")
	if err != nil {
		return nil, fmt.Errorf("URL parsing failed: %w", err)
	}
	var httpCookies []*http.Cookie

	for name, value := range cookies {
		if value != "" {
			httpCookies = append(httpCookies, &http.Cookie{
				Name:   name,
				Value:  value,
				Domain: ".linkedin.com",
				Path:   "/",
			})
		}
	}

	if len(httpCookies) == 0 {
		return nil, errors.New("no cookies provided")
	}

	jar.SetCookies(u, httpCookies)

	return &Client{
		httpClient: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
		},
		logger: slog.Default(),
	}, nil
}

// FetchProfile retrieves a LinkedIn profile from a profile URL.
func (c *Client) FetchProfile(ctx context.Context, profileURL string) (*Profile, error) {
	c.logger.InfoContext(ctx, "fetching LinkedIn profile", "url", profileURL)

	// Normalize URL
	if !strings.HasPrefix(profileURL, "http") {
		profileURL = "https://www.linkedin.com/in/" + profileURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	// Don't set Accept-Encoding - let Go's HTTP client handle compression automatically
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")

	if c.debug {
		if u, err := url.Parse(profileURL); err == nil {
			cookies := c.httpClient.Jar.Cookies(u)
			names := make([]string, len(cookies))
			for i, c := range cookies {
				names[i] = c.Name
			}
			c.logger.InfoContext(ctx, "request cookies",
				"count", len(cookies),
				"names", names)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			c.logger.WarnContext(ctx, "failed to close response body", "error", cerr)
		}
	}()

	if c.debug {
		c.logger.InfoContext(ctx, "response received",
			"status", resp.StatusCode,
			"content-type", resp.Header.Get("Content-Type"),
			"content-length", resp.Header.Get("Content-Length"))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response failed: %w", err)
	}

	if c.debug {
		// Save response to file for debugging
		tmpFile, err := os.CreateTemp("", "linkedin-response-*.html")
		if err == nil {
			defer func() {
				if cerr := tmpFile.Close(); cerr != nil {
					c.logger.WarnContext(ctx, "failed to close temp file", "error", cerr)
				}
			}()
			if _, err := tmpFile.Write(body); err == nil {
				c.logger.InfoContext(ctx, "saved response for debugging",
					"path", tmpFile.Name(),
					"size", len(body),
					"preview", string(body[:min(100, len(body))]))
			}
		}
	}

	profile, err := parseProfile(body, profileURL)
	if err != nil {
		return nil, fmt.Errorf("profile parsing failed: %w", err)
	}

	c.logger.InfoContext(ctx, "profile fetched successfully",
		"name", profile.Name,
		"employer", profile.CurrentEmployer)

	return profile, nil
}

// parseProfile extracts profile data from LinkedIn HTML response.
func parseProfile(body []byte, profileURL string) (*Profile, error) {
	content := string(body)

	profile := &Profile{ProfileURL: profileURL}

	// Extract the publicIdentifier from the URL
	target := extractPublicIdentifierFromURL(profileURL)

	// LinkedIn now embeds profile data in HTML-encoded JSON within <code> tags
	// Extract and decode all code blocks
	blocks := extractCodeBlocks(content)

	// Search through code blocks for the target profile data
	var fallback *Profile
	for _, code := range blocks {
		// Look for blocks containing profile information
		if !strings.Contains(code, `"publicIdentifier":`) {
			continue
		}

		// Try to find exact match first
		exact := false
		var section string

		switch {
		case target != "" && strings.Contains(code, fmt.Sprintf(`"publicIdentifier":%q`, target)):
			exact = true
			section = extractProfileSection(code, target)
		case fallback == nil:
			// Store first profile as fallback (since we requested this URL, it's likely the right profile)
			section = code
		default:
			continue
		}

		first := extractJSONField(section, "firstName")
		last := extractJSONField(section, "lastName")
		headline := extractJSONField(section, "headline")

		p := &Profile{ProfileURL: profileURL}

		if first != "" {
			p.Name = unescapeJSON(first)
			if last != "" {
				p.Name += " " + unescapeJSON(last)
			}
		}

		if headline != "" {
			p.Headline = unescapeJSON(headline)
		}

		// Extract location if available
		if loc := extractJSONField(section, "geoLocationName"); loc != "" {
			p.Location = unescapeJSON(loc)
		}

		// Try to find current employer from position data
		if strings.Contains(section, `"companyName":`) {
			if company := extractJSONField(section, "companyName"); company != "" {
				p.CurrentEmployer = unescapeJSON(company)
			}
		}

		// If exact match, use it immediately
		if exact && p.Name != "" {
			profile = p
			break
		}

		// Otherwise, store as fallback
		if fallback == nil && p.Name != "" {
			fallback = p
		}
	}

	// Use fallback if we didn't find exact match
	if profile.Name == "" && fallback != nil {
		profile = fallback
	}

	// Fallback: extract from meta tags if structured data unavailable
	if profile.Name == "" {
		profile.Name = extractMetaContent(content, `property="og:title"`)
	}
	if profile.Headline == "" {
		profile.Headline = extractMetaContent(content, `property="og:description"`)
	}

	if profile.Name == "" {
		return nil, errors.New("failed to extract profile name from page")
	}

	return profile, nil
}

func extractField(content, start, end string) string {
	idx := strings.Index(content, start)
	if idx == -1 {
		return ""
	}
	idx += len(start)
	endIdx := strings.Index(content[idx:], end)
	if endIdx == -1 {
		return ""
	}
	return content[idx : idx+endIdx]
}

func extractMetaContent(content, property string) string {
	idx := strings.Index(content, property)
	if idx == -1 {
		return ""
	}
	contentIdx := strings.Index(content[idx:], `content="`)
	if contentIdx == -1 {
		return ""
	}
	start := idx + contentIdx + len(`content="`)
	end := strings.Index(content[start:], `"`)
	if end == -1 {
		return ""
	}
	return unescapeJSON(content[start : start+end])
}

func unescapeJSON(s string) string {
	var unescaped string
	if err := json.Unmarshal([]byte(`"`+s+`"`), &unescaped); err != nil {
		return s
	}
	return unescaped
}

// EnableDebug enables debug logging for cookie and request information.
func (c *Client) EnableDebug() {
	c.debug = true
}

// cookiesFromEnv reads cookies from environment variables.
func cookiesFromEnv() []*http.Cookie {
	var cookies []*http.Cookie

	envMap := map[string]string{
		"LINKEDIN_LI_AT":      "li_at",
		"LINKEDIN_JSESSIONID": "JSESSIONID",
		"LINKEDIN_LIDC":       "lidc",
		"LINKEDIN_BCOOKIE":    "bcookie",
	}

	for envVar, cookieName := range envMap {
		if value := os.Getenv(envVar); value != "" {
			cookies = append(cookies, &http.Cookie{
				Name:   cookieName,
				Value:  value,
				Domain: ".linkedin.com",
				Path:   "/",
			})
		}
	}

	return cookies
}

// filterEssentialCookies returns only the minimum cookies needed for LinkedIn authentication.
// Based on testing, LinkedIn requires: li_at, JSESSIONID, and lidc for authenticated requests.
func filterEssentialCookies(cookies []*kooky.Cookie) []*kooky.Cookie {
	essentialNames := map[string]bool{
		"li_at":      true, // Authentication token - REQUIRED
		"JSESSIONID": true, // Session ID - REQUIRED
		"lidc":       true, // Data center routing - REQUIRED
		"bcookie":    true, // Browser cookie - may be required
	}

	var essential []*kooky.Cookie
	for _, c := range cookies {
		if essentialNames[c.Name] {
			essential = append(essential, c)
		}
	}
	return essential
}

// extractCodeBlocks extracts and HTML-decodes content from <code> tags.
func extractCodeBlocks(s string) []string {
	// Use (?s) flag for DOTALL mode to match across newlines
	re := regexp.MustCompile(`(?s)<code[^>]*>(.*?)</code>`)
	matches := re.FindAllStringSubmatch(s, -1)

	var blocks []string
	for _, m := range matches {
		if len(m) > 1 {
			// HTML-decode the content
			blocks = append(blocks, html.UnescapeString(m[1]))
		}
	}
	return blocks
}

// extractJSONField extracts a field value from a JSON string.
func extractJSONField(s, field string) string {
	// Look for "field":"value" pattern
	re := regexp.MustCompile(fmt.Sprintf(`%q:"([^"]*)"`, field))
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	return ""
}

// extractPublicIdentifierFromURL extracts the publicIdentifier from a LinkedIn profile URL.
func extractPublicIdentifierFromURL(s string) string {
	// Extract from URLs like https://www.linkedin.com/in/solar/ or https://www.linkedin.com/in/thomas-strömberg-9977261/
	// Note: LinkedIn uses vanity URLs which may differ from the actual publicIdentifier
	re := regexp.MustCompile(`/in/([^/]+)`)
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		slug := m[1]
		// URL decode if needed
		if strings.Contains(slug, "%") {
			if decoded, err := url.QueryUnescape(slug); err == nil {
				return decoded
			}
		}
		return slug
	}
	return ""
}

// extractProfileSection extracts a section of JSON around the matching publicIdentifier.
func extractProfileSection(s, id string) string {
	// Find the position of the publicIdentifier
	search := fmt.Sprintf(`"publicIdentifier":%q`, id)
	idx := strings.Index(s, search)
	if idx == -1 {
		return s // Return full block if not found
	}

	// Extract a window around the publicIdentifier (look backwards and forwards)
	start := max(0, idx-5000)
	end := min(len(s), idx+5000)

	return s[start:end]
}

// tryFirefoxProfiles attempts to read cookies from Firefox profiles, including Developer Edition.
func tryFirefoxProfiles(ctx context.Context) []*kooky.Cookie {
	home := os.Getenv("HOME")
	if home == "" {
		return nil
	}

	dir := filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
	pattern := filepath.Join(dir, "*", "cookies.sqlite")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}

	// Try each profile until we find LinkedIn cookies
	for _, f := range matches {
		cookies, err := firefox.ReadCookies(ctx, f, kooky.Valid, kooky.DomainHasSuffix("linkedin.com"))
		if err == nil && len(cookies) > 0 {
			slog.InfoContext(ctx, "found Firefox cookies",
				"profile", filepath.Base(filepath.Dir(f)),
				"count", len(cookies))
			return cookies
		}
	}

	return nil
}
