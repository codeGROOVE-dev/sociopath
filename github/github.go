// Package github fetches GitHub profile data.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/profile"
)

const platform = "github"

// Match returns true if the URL is a GitHub profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "github.com/") {
		return false
	}
	// Extract path after github.com/
	idx := strings.Index(lower, "github.com/")
	path := lower[idx+len("github.com/"):]
	path = strings.TrimSuffix(path, "/")
	if qIdx := strings.Index(path, "?"); qIdx >= 0 {
		path = path[:qIdx]
	}
	// Must be just username (no slashes)
	if strings.Contains(path, "/") {
		return false
	}
	// Skip known non-profile paths
	nonProfiles := map[string]bool{
		"features": true, "security": true, "enterprise": true, "team": true,
		"marketplace": true, "sponsors": true, "topics": true, "trending": true,
		"collections": true, "orgs": true, "solutions": true, "resources": true,
		"customer-stories": true, "partners": true, "accelerator": true,
		"trust-center": true, "why-github": true, "mcp": true, "fluidicon": true,
		"login": true, "join": true, "pricing": true, "about": true,
		"premium-support": true, "newsletter": true, "edu": true, "mobile": true,
		"readme": true, "explore": true, "new": true, "settings": true,
		"notifications": true, "issues": true, "pulls": true, "codespaces": true,
		"copilot": true, "actions": true, "projects": true, "packages": true,
		"discussions": true, "wiki": true, "stars": true, "watching": true,
		"search": true, "site": true, "apps": true,
	}
	return path != "" && !nonProfiles[path]
}

// AuthRequired returns false because GitHub profiles are public.
func AuthRequired() bool { return false }

// Client handles GitHub requests.
type Client struct {
	httpClient *http.Client
	cache      profile.HTTPCache
	logger     *slog.Logger
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache  profile.HTTPCache
	logger *slog.Logger
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(cache profile.HTTPCache) Option {
	return func(c *config) { c.cache = cache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates a GitHub client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 3 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a GitHub profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	// Normalize URL
	if !strings.HasPrefix(urlStr, "http") {
		urlStr = "https://github.com/" + username
	}

	c.logger.InfoContext(ctx, "fetching github profile", "url", urlStr, "username", username)

	// Fetch API data
	p, err := c.fetchAPI(ctx, urlStr, username)
	if err != nil {
		return nil, err
	}

	// Also fetch HTML to extract rel="me" links (Mastodon, etc.)
	htmlLinks := c.fetchHTMLLinks(ctx, urlStr)
	p.SocialLinks = append(p.SocialLinks, htmlLinks...)

	// Fetch user's README if available
	readme := c.fetchREADME(ctx, username)
	if readme != "" {
		p.Unstructured = readme
		// Extract social links from README markdown
		readmeLinks := htmlutil.SocialLinks(readme)
		p.SocialLinks = append(p.SocialLinks, readmeLinks...)
	}

	// Deduplicate and filter out same-platform links (GitHub to GitHub)
	p.SocialLinks = dedupeLinks(p.SocialLinks)
	p.SocialLinks = filterSamePlatformLinks(p.SocialLinks)

	return p, nil
}

func (c *Client) fetchAPI(ctx context.Context, urlStr, username string) (*profile.Profile, error) {
	apiURL := "https://api.github.com/users/" + username

	// Check cache
	if c.cache != nil {
		if data, _, _, found := c.cache.Get(ctx, apiURL); found {
			return parseJSON(data, urlStr, username)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "sociopath/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // error ignored intentionally

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	// Cache response (async, errors intentionally ignored)
	if c.cache != nil {
		_ = c.cache.SetAsync(ctx, apiURL, body, "", nil) //nolint:errcheck // async, error ignored
	}

	return parseJSON(body, urlStr, username)
}

func (c *Client) fetchHTMLLinks(ctx context.Context, urlStr string) []string {
	// Check cache
	if c.cache != nil {
		if data, _, _, found := c.cache.Get(ctx, urlStr); found {
			return extractSocialLinks(string(data))
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		c.logger.Debug("failed to create HTML request", "error", err)
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Debug("failed to fetch HTML", "error", err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // error ignored intentionally

	if resp.StatusCode != http.StatusOK {
		c.logger.Debug("HTML fetch returned non-200", "status", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		c.logger.Debug("failed to read HTML body", "error", err)
		return nil
	}

	// Cache response (async, errors intentionally ignored)
	if c.cache != nil {
		_ = c.cache.SetAsync(ctx, urlStr, body, "", nil) //nolint:errcheck // async, error ignored
	}

	return extractSocialLinks(string(body))
}

func (c *Client) fetchREADME(ctx context.Context, username string) string {
	// Try main branch first, then master as fallback
	branches := []string{"main", "master"}

	for _, branch := range branches {
		readmeURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/refs/heads/%s/README.md", username, username, branch)

		// Check cache
		if c.cache != nil {
			if data, _, _, found := c.cache.Get(ctx, readmeURL); found {
				return string(data)
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, readmeURL, http.NoBody)
		if err != nil {
			c.logger.Debug("failed to create README request", "error", err, "branch", branch)
			continue
		}
		req.Header.Set("User-Agent", "sociopath/1.0")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.logger.Debug("failed to fetch README", "error", err, "branch", branch)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close() //nolint:errcheck // error ignored intentionally
			c.logger.Debug("README fetch returned non-200", "status", resp.StatusCode, "branch", branch)
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close() //nolint:errcheck // error ignored intentionally
		if err != nil {
			c.logger.Debug("failed to read README body", "error", err, "branch", branch)
			continue
		}

		readme := string(body)

		// Cache response (async, errors intentionally ignored)
		if c.cache != nil {
			_ = c.cache.SetAsync(ctx, readmeURL, body, "", nil) //nolint:errcheck // async, error ignored
		}

		c.logger.Debug("successfully fetched README", "branch", branch, "size", len(readme))
		return readme
	}

	c.logger.Debug("no README found for user", "username", username)
	return ""
}

// extractSocialLinks extracts social media links from HTML, focusing on rel="me" verified links.
func extractSocialLinks(html string) []string {
	var links []string

	// GitHub uses rel="nofollow me" for verified social links
	// Example: <a rel="nofollow me" href="https://triangletoot.party/@thomrstrom">...</a>
	relMePattern := regexp.MustCompile(`<a[^>]+rel=["'][^"']*\bme\b[^"']*["'][^>]+href=["']([^"']+)["']`)
	matches := relMePattern.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			link := match[1]
			// Filter out GitHub URLs and email URLs
			if !strings.Contains(link, "github.com") && !htmlutil.IsEmailURL(link) {
				links = append(links, link)
			}
		}
	}

	// Also check for href first, then rel (both orders work)
	hrefFirstPattern := regexp.MustCompile(`<a[^>]+href=["']([^"']+)["'][^>]+rel=["'][^"']*\bme\b[^"']*["']`)
	matches = hrefFirstPattern.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) <= 1 {
			continue
		}
		link := match[1]
		// Skip GitHub links, email URLs, and duplicates
		if strings.Contains(link, "github.com") || htmlutil.IsEmailURL(link) {
			continue
		}
		isDuplicate := false
		for _, existing := range links {
			if existing == link {
				isDuplicate = true
				break
			}
		}
		if !isDuplicate {
			links = append(links, link)
		}
	}

	return links
}

func parseJSON(data []byte, urlStr, _ string) (*profile.Profile, error) {
	//nolint:govet // fieldalignment: intentional layout for readability
	var ghUser struct {
		Login       string `json:"login"`
		Name        string `json:"name"`
		Bio         string `json:"bio"`
		Location    string `json:"location"`
		Blog        string `json:"blog"`
		Email       string `json:"email"`
		TwitterUser string `json:"twitter_username"`
		Company     string `json:"company"`
		PublicRepos int    `json:"public_repos"`
		Followers   int    `json:"followers"`
		Following   int    `json:"following"`
		AvatarURL   string `json:"avatar_url"`
		HTMLURL     string `json:"html_url"`
		Type        string `json:"type"`
	}

	if err := json.Unmarshal(data, &ghUser); err != nil {
		return nil, err
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      ghUser.Login,
		Name:          ghUser.Name,
		Bio:           ghUser.Bio,
		Location:      ghUser.Location,
		Fields:        make(map[string]string),
	}

	// Add website or email
	if ghUser.Blog != "" {
		// GitHub sometimes stores URLs without protocol
		website := ghUser.Blog
		if !strings.HasPrefix(website, "http") {
			website = "https://" + website
		}

		// Check if this is actually an email address with http(s):// prefix
		if email, isEmail := htmlutil.ExtractEmailFromURL(website); isEmail {
			p.Fields["email"] = email
		} else {
			p.Website = website
			p.Fields["website"] = website
			// Don't add to SocialLinks - it's already in p.Website which is followed by recursive mode
		}
	}

	// Add email
	if ghUser.Email != "" {
		p.Fields["email"] = ghUser.Email
	}

	// Add company
	if ghUser.Company != "" {
		// Remove @ prefix if present
		company := strings.TrimPrefix(ghUser.Company, "@")
		p.Fields["company"] = company
	}

	// Add Twitter username
	if ghUser.TwitterUser != "" {
		twitterURL := "https://twitter.com/" + ghUser.TwitterUser
		p.Fields["twitter"] = twitterURL
		p.SocialLinks = append(p.SocialLinks, twitterURL)
	}

	// Add stats
	if ghUser.PublicRepos > 0 {
		p.Fields["public_repos"] = strconv.Itoa(ghUser.PublicRepos)
	}
	if ghUser.Followers > 0 {
		p.Fields["followers"] = strconv.Itoa(ghUser.Followers)
	}
	if ghUser.Following > 0 {
		p.Fields["following"] = strconv.Itoa(ghUser.Following)
	}

	// Add avatar URL
	if ghUser.AvatarURL != "" {
		p.Fields["avatar_url"] = ghUser.AvatarURL
	}

	// Add account type
	if ghUser.Type != "" {
		p.Fields["type"] = ghUser.Type
	}

	return p, nil
}

func extractUsername(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "www.")

	// Extract github.com/username
	re := regexp.MustCompile(`github\.com/([^/?]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func filterSamePlatformLinks(links []string) []string {
	var filtered []string
	for _, link := range links {
		// Skip GitHub URLs
		if !Match(link) {
			filtered = append(filtered, link)
		}
	}
	return filtered
}

func dedupeLinks(links []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, link := range links {
		normalized := strings.TrimSuffix(strings.ToLower(link), "/")
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, link)
		}
	}
	return result
}
