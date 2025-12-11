// Package github fetches GitHub profile data.
package github

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "github"

// profileTimezoneRegex extracts the UTC offset from GitHub's profile-timezone element.
// Example: <profile-timezone data-hours-ahead-of-utc="-8.0">(UTC -08:00)</profile-timezone>.
var profileTimezoneRegex = regexp.MustCompile(`<profile-timezone[^>]*data-hours-ahead-of-utc="([^"]*)"`)

// extractUTCOffset parses the UTC offset from GitHub profile HTML.
// Returns nil if no timezone is found or the value is invalid.
func extractUTCOffset(html string) *float64 {
	matches := profileTimezoneRegex.FindStringSubmatch(html)
	if len(matches) < 2 || matches[1] == "" {
		return nil
	}
	offset, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return nil
	}
	return &offset
}

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
	cache      httpcache.Cacher
	logger     *slog.Logger
	token      string
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache  httpcache.Cacher
	logger *slog.Logger
	token  string
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache httpcache.Cacher) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// WithToken sets the GitHub API token.
func WithToken(token string) Option {
	return func(c *config) { c.token = token }
}

// New creates a GitHub client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	// Ensure logger is not nil
	logger := cfg.logger
	if logger == nil {
		logger = slog.Default()
	}

	// Try to get token from environment if not provided
	token := cfg.token
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	if token == "" {
		logger.WarnContext(ctx, "GITHUB_TOKEN not set - GitHub API requests will be rate-limited to 60/hour")
	} else {
		logger.InfoContext(ctx, "using GITHUB_TOKEN for authenticated API requests")
	}

	return &Client{
		httpClient: &http.Client{Timeout: 3 * time.Second},
		cache:      cfg.cache,
		logger:     logger,
		token:      token,
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

	// Fetch API data, with fallback to HTML scraping on failure
	prof, apiErr := c.fetchAPI(ctx, urlStr, username)

	// Fetch HTML to extract rel="me" links, README, and organizations
	htmlContent, htmlLinks := c.fetchHTML(ctx, urlStr)

	// If API failed, try to build profile from HTML
	if apiErr != nil {
		var gitHubAPIErr *APIError
		if errors.As(apiErr, &gitHubAPIErr) {
			if gitHubAPIErr.IsRateLimit {
				c.logger.WarnContext(ctx, "GitHub API rate limited, falling back to HTML scraping",
					"url", urlStr,
					"reset_time", gitHubAPIErr.RateLimitReset.Format(time.RFC3339),
				)
			} else {
				c.logger.WarnContext(ctx, "GitHub API access denied, falling back to HTML scraping",
					"url", urlStr,
					"status", gitHubAPIErr.StatusCode,
				)
			}
		} else {
			c.logger.WarnContext(ctx, "GitHub API request failed, falling back to HTML scraping",
				"url", urlStr,
				"error", apiErr,
			)
		}

		// Try to build profile from HTML
		if htmlContent == "" {
			return nil, fmt.Errorf("API failed and no HTML content available: %w", apiErr)
		}

		prof = c.parseProfileFromHTML(ctx, htmlContent, urlStr, username)
		c.logger.InfoContext(ctx, "built profile from HTML scraping", "url", urlStr, "username", username)
	}

	prof.SocialLinks = append(prof.SocialLinks, htmlLinks...)

	// Extract README, organizations, and UTC offset from HTML if available
	if htmlContent != "" {
		// Extract UTC offset from profile-timezone element
		prof.UTCOffset = extractUTCOffset(htmlContent)

		// Extract organizations
		orgs := extractOrganizations(htmlContent)
		if len(orgs) > 0 {
			prof.Fields["organizations"] = strings.Join(orgs, ", ")
		}

		// Extract README - get raw HTML for link extraction, then convert to markdown
		readmeHTML := extractREADMEHTML(htmlContent)
		if readmeHTML != "" {
			// Extract social links from raw HTML (before conversion loses image-only links)
			readmeLinks := htmlutil.SocialLinks(readmeHTML)
			prof.SocialLinks = append(prof.SocialLinks, readmeLinks...)

			// Convert to markdown for unstructured content
			prof.Unstructured = htmlutil.ToMarkdown(readmeHTML)
		}
	}

	// Deduplicate and filter out same-platform links (GitHub to GitHub)
	prof.SocialLinks = dedupeLinks(prof.SocialLinks)
	prof.SocialLinks = filterSamePlatformLinks(prof.SocialLinks)

	return prof, nil
}

// APIError contains details about a GitHub API error.
//
//nolint:govet // fieldalignment: intentional layout for readability
type APIError struct {
	StatusCode      int
	RateLimitRemain int
	RateLimitReset  time.Time
	Message         string
	IsRateLimit     bool
}

func (e *APIError) Error() string {
	if e.IsRateLimit {
		return fmt.Sprintf("GitHub API rate limited (resets at %s): %s", e.RateLimitReset.Format(time.RFC3339), e.Message)
	}
	return fmt.Sprintf("GitHub API error %d: %s", e.StatusCode, e.Message)
}

func (c *Client) fetchAPI(ctx context.Context, urlStr, username string) (*profile.Profile, error) {
	// Try GraphQL first (gets social accounts), fall back to REST API
	if c.token != "" {
		prof, err := c.fetchGraphQL(ctx, urlStr, username)
		if err == nil {
			return prof, nil
		}
		c.logger.WarnContext(ctx, "GraphQL fetch failed, falling back to REST API", "error", err)
	}

	// REST API fallback
	apiURL := "https://api.github.com/users/" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "sociopath/1.0")

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	body, err := c.doAPIRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	return parseJSON(body, urlStr, username)
}

func (c *Client) fetchGraphQL(ctx context.Context, urlStr, username string) (*profile.Profile, error) {
	query := `
	query($login: String!) {
		user(login: $login) {
			name
			login
			location
			bio
			company
			websiteUrl
			twitterUsername
			createdAt
			updatedAt

			socialAccounts(first: 10) {
				nodes {
					provider
					url
					displayName
				}
			}

			followers {
				totalCount
			}
			following {
				totalCount
			}

			repositories(first: 1, ownerAffiliations: OWNER) {
				totalCount
			}
		}
	}
	`

	variables := map[string]string{"login": username}
	reqBody := map[string]any{
		"query":     query,
		"variables": variables,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling GraphQL request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.github.com/graphql", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sociopath/1.0")

	body, err := c.doAPIRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	return parseGraphQLResponse(body, urlStr, username)
}

func parseGraphQLResponse(data []byte, urlStr, _ string) (*profile.Profile, error) {
	var response struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
		Data struct {
			User struct {
				Name           string `json:"name"`
				Login          string `json:"login"`
				Location       string `json:"location"`
				Bio            string `json:"bio"`
				Company        string `json:"company"`
				WebsiteURL     string `json:"websiteUrl"`
				TwitterUser    string `json:"twitterUsername"`
				CreatedAt      string `json:"createdAt"`
				UpdatedAt      string `json:"updatedAt"`
				SocialAccounts struct {
					Nodes []struct {
						URL         string `json:"url"`
						Provider    string `json:"provider"`
						DisplayName string `json:"displayName"`
					} `json:"nodes"`
				} `json:"socialAccounts"`
				Followers    struct{ TotalCount int } `json:"followers"`
				Following    struct{ TotalCount int } `json:"following"`
				Repositories struct{ TotalCount int } `json:"repositories"`
			} `json:"user"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("parsing GraphQL response: %w", err)
	}

	if len(response.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error: %s", response.Errors[0].Message)
	}

	user := response.Data.User
	prof := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: true,
		Username:      user.Login,
		Name:          strings.TrimSpace(user.Name),
		Bio:           strings.TrimSpace(user.Bio),
		Location:      strings.TrimSpace(user.Location),
		Fields:        make(map[string]string),
	}

	// Add website
	if user.WebsiteURL != "" {
		website := user.WebsiteURL
		if !strings.HasPrefix(website, "http") {
			website = "https://" + website
		}
		prof.Website = website
		prof.Fields["website"] = website
	}

	// Add company
	if user.Company != "" {
		company := strings.TrimSpace(strings.TrimPrefix(user.Company, "@"))
		prof.Fields["company"] = company
	}

	// Add stats
	if user.Repositories.TotalCount > 0 {
		prof.Fields["public_repos"] = strconv.Itoa(user.Repositories.TotalCount)
	}
	if user.Followers.TotalCount > 0 {
		prof.Fields["followers"] = strconv.Itoa(user.Followers.TotalCount)
	}
	if user.Following.TotalCount > 0 {
		prof.Fields["following"] = strconv.Itoa(user.Following.TotalCount)
	}

	// Add Twitter from GraphQL
	if user.TwitterUser != "" {
		twitterURL := "https://twitter.com/" + user.TwitterUser
		prof.Fields["twitter"] = twitterURL
		prof.SocialLinks = append(prof.SocialLinks, twitterURL)
	}

	// Add social accounts from GraphQL - this is the key improvement!
	for _, social := range user.SocialAccounts.Nodes {
		if social.URL != "" {
			prof.SocialLinks = append(prof.SocialLinks, social.URL)
		}
	}

	// Add account timestamps
	if user.CreatedAt != "" {
		prof.CreatedAt = user.CreatedAt
	}
	if user.UpdatedAt != "" {
		prof.UpdatedAt = user.UpdatedAt
	}

	return prof, nil
}

func (c *Client) doAPIRequest(ctx context.Context, req *http.Request) ([]byte, error) {
	// Build cache key - for POST requests, include body hash to differentiate queries
	cacheKey := req.URL.String()
	if req.Method == http.MethodPost && req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("reading request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		hash := sha256.Sum256(bodyBytes)
		cacheKey = req.URL.String() + ":" + hex.EncodeToString(hash[:])
	}

	if c.cache == nil {
		c.logger.InfoContext(ctx, "cache disabled", "url", req.URL.String())
		return c.executeAPIRequest(ctx, req)
	}

	data, err := c.cache.GetSet(ctx, httpcache.URLToKey(cacheKey), func(_ context.Context) ([]byte, error) {
		body, fetchErr := c.executeAPIRequest(ctx, req)
		if fetchErr != nil {
			// Cache API errors to avoid hammering servers.
			var apiErr *APIError
			if errors.As(fetchErr, &apiErr) {
				return fmt.Appendf(nil, "ERROR:%d", apiErr.StatusCode), nil
			}
			return nil, fetchErr
		}
		return body, nil
	})
	if err != nil {
		return nil, err
	}

	// Check if this is a cached error.
	if s := string(data); strings.HasPrefix(s, "ERROR:") {
		code, _ := strconv.Atoi(strings.TrimPrefix(s, "ERROR:")) //nolint:errcheck // 0 is acceptable default
		return nil, &APIError{StatusCode: code, Message: "cached error"}
	}

	return data, nil
}

func (c *Client) executeAPIRequest(ctx context.Context, req *http.Request) ([]byte, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // error ignored intentionally

	// Parse rate limit headers (parse errors default to 0).
	rateLimitRemain, _ := strconv.Atoi(resp.Header.Get("X-Ratelimit-Remaining"))        //nolint:errcheck // 0 is acceptable default
	rateLimitReset, _ := strconv.ParseInt(resp.Header.Get("X-Ratelimit-Reset"), 10, 64) //nolint:errcheck // 0 is acceptable default
	resetTime := time.Unix(rateLimitReset, 0)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // best effort read of error body
		isRateLimit := resp.StatusCode == http.StatusForbidden && rateLimitRemain == 0

		apiErr := &APIError{
			StatusCode:      resp.StatusCode,
			RateLimitRemain: rateLimitRemain,
			RateLimitReset:  resetTime,
			Message:         string(body),
			IsRateLimit:     isRateLimit,
		}

		c.logger.WarnContext(ctx, "GitHub API request failed",
			"url", req.URL.String(),
			"status", resp.StatusCode,
			"rate_limit_remaining", rateLimitRemain,
			"rate_limit_reset", resetTime.Format(time.RFC3339),
			"is_rate_limit", isRateLimit,
			"response_body", string(body),
		)

		return nil, apiErr
	}

	return io.ReadAll(resp.Body)
}

func (c *Client) fetchHTML(ctx context.Context, urlStr string) (content string, links []string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		c.logger.Debug("failed to create HTML request", "error", err)
		return "", nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		c.logger.Debug("failed to fetch HTML", "error", err)
		return "", nil
	}

	content = string(body)
	links = extractSocialLinks(content)
	return content, links
}

// extractREADMEHTML extracts the raw README HTML from GitHub profile page.
func extractREADMEHTML(htmlContent string) string {
	// GitHub embeds README in <article class="markdown-body entry-content ...">
	// Extract everything from the opening tag to the closing </article>
	articlePattern := regexp.MustCompile(`(?s)<article[^>]*class="[^"]*markdown-body[^"]*"[^>]*>(.*?)</article>`)
	matches := articlePattern.FindStringSubmatch(htmlContent)
	if len(matches) < 2 {
		return ""
	}

	readmeHTML := matches[1]
	if strings.TrimSpace(readmeHTML) == "" {
		return ""
	}

	return readmeHTML
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
		if !slices.Contains(links, link) {
			links = append(links, link)
		}
	}

	return links
}

// extractOrganizations extracts organization names from GitHub profile HTML.
// Organizations are listed in the profile sidebar with aria-label attributes.
func extractOrganizations(html string) []string {
	// Pattern: aria-label="organizationname"
	// This matches the organization links in the profile sidebar
	pattern := regexp.MustCompile(`aria-label="([^"]+)"[^>]*>\s*<img[^>]+alt="@([^"]+)"`)
	matches := pattern.FindAllStringSubmatch(html, -1)

	var orgs []string
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) > 2 {
			orgName := match[1]
			// Skip if already seen
			if seen[orgName] {
				continue
			}
			seen[orgName] = true
			orgs = append(orgs, orgName)
		}
	}

	// Fallback pattern: just look for organization links
	if len(orgs) == 0 {
		linkPattern := regexp.MustCompile(`href="/([^/"]+)"[^>]*aria-label="([^"]+)"`)
		matches = linkPattern.FindAllStringSubmatch(html, -1)
		for _, match := range matches {
			if len(match) > 2 {
				orgName := match[2]
				// Filter out obviously non-org labels
				if strings.Contains(strings.ToLower(orgName), "organization") ||
					len(orgName) < 50 && !strings.Contains(orgName, " ") {
					if !seen[orgName] {
						seen[orgName] = true
						orgs = append(orgs, orgName)
					}
				}
			}
		}
	}

	return orgs
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
		CreatedAt   string `json:"created_at"`
		UpdatedAt   string `json:"updated_at"`
	}

	if err := json.Unmarshal(data, &ghUser); err != nil {
		return nil, err
	}

	prof := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      ghUser.Login,
		Name:          strings.TrimSpace(ghUser.Name),
		Bio:           strings.TrimSpace(ghUser.Bio),
		Location:      strings.TrimSpace(ghUser.Location),
		Fields:        make(map[string]string),
	}

	// Add website or email
	if ghUser.Blog != "" {
		blog := ghUser.Blog
		blogLower := strings.ToLower(blog)

		// Check for mailto: links first
		if email, found := strings.CutPrefix(blogLower, "mailto:"); found {
			prof.Fields["email"] = email
		} else {
			// GitHub sometimes stores URLs without protocol
			website := blog
			if !strings.HasPrefix(website, "http") {
				website = "https://" + website
			}

			// Check if this is actually an email address with http(s):// prefix
			if email, isEmail := htmlutil.ExtractEmailFromURL(website); isEmail {
				prof.Fields["email"] = email
			} else {
				prof.Website = website
				prof.Fields["website"] = website
				// Don't add to SocialLinks - it's already in prof.Website which is followed by recursive mode
			}
		}
	}

	// Add email
	if ghUser.Email != "" {
		prof.Fields["email"] = ghUser.Email
	}

	// Add company
	if ghUser.Company != "" {
		// Remove @ prefix if present
		company := strings.TrimSpace(strings.TrimPrefix(ghUser.Company, "@"))
		prof.Fields["company"] = company
	}

	// Add Twitter username
	if ghUser.TwitterUser != "" {
		twitterURL := "https://twitter.com/" + ghUser.TwitterUser
		prof.Fields["twitter"] = twitterURL
		prof.SocialLinks = append(prof.SocialLinks, twitterURL)
	}

	// Add stats
	if ghUser.PublicRepos > 0 {
		prof.Fields["public_repos"] = strconv.Itoa(ghUser.PublicRepos)
	}
	if ghUser.Followers > 0 {
		prof.Fields["followers"] = strconv.Itoa(ghUser.Followers)
	}
	if ghUser.Following > 0 {
		prof.Fields["following"] = strconv.Itoa(ghUser.Following)
	}

	// Add avatar URL
	if ghUser.AvatarURL != "" {
		prof.AvatarURL = ghUser.AvatarURL
	}

	// Add account type
	if ghUser.Type != "" {
		prof.Fields["type"] = ghUser.Type
	}

	// Add account timestamps
	if ghUser.CreatedAt != "" {
		prof.CreatedAt = ghUser.CreatedAt
	}
	if ghUser.UpdatedAt != "" {
		prof.UpdatedAt = ghUser.UpdatedAt
	}

	return prof, nil
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

// parseProfileFromHTML extracts profile data from GitHub HTML when API is unavailable.
func (c *Client) parseProfileFromHTML(ctx context.Context, html, urlStr, username string) *profile.Profile {
	prof := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Extract full name: <span class="p-name vcard-fullname..." itemprop="name">
	namePattern := regexp.MustCompile(`<span[^>]+class="[^"]*p-name[^"]*"[^>]*itemprop="name"[^>]*>\s*([^<]+)`)
	if matches := namePattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Name = strings.TrimSpace(matches[1])
	}

	// Extract bio: <div class="p-note user-profile-bio..." data-bio-text="...">
	bioPattern := regexp.MustCompile(`data-bio-text="([^"]+)"`)
	if matches := bioPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Bio = strings.TrimSpace(matches[1])
	}

	// Extract location: <li... itemprop="homeLocation"... aria-label="Home location: ...">
	locPattern := regexp.MustCompile(`itemprop="homeLocation"[^>]*aria-label="Home location:\s*([^"]+)"`)
	if matches := locPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Location = strings.TrimSpace(matches[1])
	}

	// Extract website: <li itemprop="url" data-test-selector="profile-website-url"...>...<a...href="...">
	websitePattern := regexp.MustCompile(`(?s)itemprop="url"[^>]*data-test-selector="profile-website-url"[^>]*>.*?href="([^"]+)"`)
	if matches := websitePattern.FindStringSubmatch(html); len(matches) > 1 {
		website := matches[1]
		if !strings.HasPrefix(website, "http") {
			website = "https://" + website
		}
		prof.Website = website
		prof.Fields["website"] = website
	}

	// Extract avatar URL
	avatarPattern := regexp.MustCompile(`<img[^>]+class="[^"]*avatar avatar-user[^"]*"[^>]+src="([^"]+)"`)
	if matches := avatarPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.AvatarURL = matches[1]
	}

	c.logger.DebugContext(ctx, "parsed profile from HTML",
		"username", username,
		"name", prof.Name,
		"bio", prof.Bio,
		"location", prof.Location,
		"website", prof.Website,
	)

	return prof
}
