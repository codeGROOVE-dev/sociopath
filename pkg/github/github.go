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
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "github"

// platformInfo implements profile.Platform for GitHub.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() {
	profile.RegisterWithFetcher(platformInfo{}, fetchProfile)
}

// fetchProfile is the FetchFunc for GitHub profiles.
func fetchProfile(ctx context.Context, url string, cfg *profile.FetcherConfig) (*profile.Profile, error) {
	var opts []Option
	if cfg != nil {
		if cfg.Logger != nil {
			opts = append(opts, WithLogger(cfg.Logger))
		}
		if cfg.GitHubToken != "" {
			opts = append(opts, WithToken(cfg.GitHubToken))
		}
		if c, ok := cfg.Cache.(httpcache.Cacher); ok {
			opts = append(opts, WithHTTPCache(c))
		}
	}
	client, err := New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

const scopeCacheTTL = 24 * time.Hour

// getCachedGhToken returns the gh auth token, using the cache.
func getCachedGhToken(ctx context.Context, cache httpcache.Cacher) string {
	if cache == nil {
		return ghAuthToken(ctx)
	}

	data, err := cache.GetSet(ctx, "github:gh_auth_token", func(ctx context.Context) ([]byte, error) {
		token := ghAuthToken(ctx)
		if token == "" {
			return nil, errors.New("no gh token")
		}
		return []byte(token), nil
	}, scopeCacheTTL)
	if err != nil {
		return ""
	}
	return string(data)
}

// profileTimezoneRegex extracts the UTC offset from GitHub's profile-timezone element.
// Example: <profile-timezone data-hours-ahead-of-utc="-8.0">(UTC -08:00)</profile-timezone>.
var profileTimezoneRegex = regexp.MustCompile(`<profile-timezone[^>]*data-hours-ahead-of-utc="([^"]*)"`)

// achievementPattern extracts achievement names and tiers from profile HTML.
// Example: alt="Achievement: Pull Shark" ... achievement-tier-label--bronze ... >x2<.
var achievementPattern = regexp.MustCompile(`alt="Achievement:\s*([^"]+)"[^>]*>(?:<span[^>]*achievement-tier-label--(\w+)[^>]*>x(\d+)</span>)?`)

// extractAchievements parses GitHub achievements from profile HTML.
// Returns a comma-separated list like "Pair Extraordinaire (gold x4), Mars 2020 Contributor".
func extractAchievements(html string) string {
	matches := achievementPattern.FindAllStringSubmatch(html, -1)
	if len(matches) == 0 {
		return ""
	}

	seen := make(map[string]bool)
	var achievements []string

	for _, m := range matches {
		name := strings.TrimSpace(m[1])
		if seen[name] {
			continue
		}
		seen[name] = true

		if m[2] != "" && m[3] != "" {
			achievements = append(achievements, fmt.Sprintf("%s (%s x%s)", name, m[2], m[3]))
		} else {
			achievements = append(achievements, name)
		}
	}

	return strings.Join(achievements, ", ")
}

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

	// Fall back to gh CLI auth token (cached for 24 hours)
	if token == "" {
		if ghToken := getCachedGhToken(ctx, cfg.cache); ghToken != "" {
			token = ghToken
			logger.InfoContext(ctx, "using token from gh auth token")
		}
	}

	if token == "" {
		logger.WarnContext(ctx, "GITHUB_TOKEN not set - GitHub API requests will be rate-limited to 60/hour")
	} else if os.Getenv("GITHUB_TOKEN") != "" {
		logger.InfoContext(ctx, "using GITHUB_TOKEN for authenticated API requests")
	}

	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
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

	// Fetch API and HTML in parallel for better performance
	var (
		prof        *profile.Profile
		apiErr      error
		htmlContent string
		htmlLinks   []string
	)

	var g errgroup.Group

	g.Go(func() error {
		prof, apiErr = c.fetchAPI(ctx, urlStr, username)
		return nil // errors handled via apiErr
	})

	g.Go(func() error {
		htmlContent, htmlLinks = c.fetchHTML(ctx, urlStr)
		return nil
	})

	_ = g.Wait() //nolint:errcheck // errors returned via apiErr

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
			// For 404 errors, try to recover from Internet Archive
			var gitHubErr *APIError
			if errors.As(apiErr, &gitHubErr) && gitHubErr.StatusCode == http.StatusNotFound {
				c.logger.InfoContext(ctx, "user not found, checking Internet Archive", "username", username)
				if recoveredProf, err := c.handleMissingUser(ctx, username, urlStr); err == nil {
					return recoveredProf, nil
				}
			}
			return nil, fmt.Errorf("API failed and no HTML content available: %w", apiErr)
		}

		prof = c.parseProfileFromHTML(ctx, htmlContent, urlStr, username)
		c.logger.InfoContext(ctx, "built profile from HTML scraping", "url", urlStr, "username", username)
	}

	prof.SocialLinks = append(prof.SocialLinks, htmlLinks...)

	// Extract README, organizations, UTC offset, email, and Pro status from HTML if available
	if htmlContent != "" {
		// Extract UTC offset from profile-timezone element
		prof.UTCOffset = extractUTCOffset(htmlContent)

		// Extract email from HTML (visible to authenticated users)
		if email := extractEmail(htmlContent); email != "" && prof.Fields["email"] == "" {
			prof.Fields["email"] = email
		}

		// Pro badge: <span title="Label: Pro" ...> (only visible in HTML, not API)
		if strings.Contains(htmlContent, `title="Label: Pro"`) {
			prof.Fields["pro"] = "true"
		}

		// Extract achievements (only visible in HTML)
		if achievements := extractAchievements(htmlContent); achievements != "" {
			prof.Fields["achievements"] = achievements
		}

		// Extract organizations
		orgs := extractOrganizations(htmlContent)
		if len(orgs) > 0 {
			prof.Fields["organizations"] = strings.Join(orgs, ", ")
		}

		// Extract pinned/popular repositories
		prof.Repositories = extractPinnedRepos(htmlContent)

		// Extract README HTML
		readmeHTML := extractREADMEHTML(htmlContent)
		if readmeHTML != "" {
			// Extract social links from raw HTML
			readmeLinks := htmlutil.SocialLinks(readmeHTML)
			prof.SocialLinks = append(prof.SocialLinks, readmeLinks...)

			// Store raw HTML - preserves all signal (alt text, URLs, structure)
			prof.Content = readmeHTML
		}

		// Extract Discord username from README or Bio
		discordContent := prof.Bio + " " + prof.Content
		if discord := htmlutil.ExtractDiscordUsername(discordContent); discord != "" {
			prof.Fields["discord"] = discord
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

// graphQLUserFields contains all the fields we want to fetch from the User object.
// email requires user:email scope, so we have a separate query without it as fallback.
const graphQLUserFieldsWithEmail = `
	name
	login
	location
	bio
	company
	email
	websiteUrl
	twitterUsername
	avatarUrl
	pronouns
	isHireable
	isBountyHunter
	isCampusExpert
	isDeveloperProgramMember
	isGitHubStar
	isSiteAdmin
	isEmployee
	hasSponsorsListing
	createdAt
	updatedAt

	status {
		message
		emoji
	}

	databaseId
	pinnedItemsRemaining

	socialAccounts(first: 10) {
		nodes {
			provider
			url
			displayName
		}
	}

	topRepositories(first: 1, orderBy: {field: STARGAZERS, direction: DESC}) {
		totalCount
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

	gists(first: 5, privacy: PUBLIC, orderBy: {field: CREATED_AT, direction: DESC}) {
		totalCount
		nodes {
			name
			description
			url
			createdAt
		}
	}

	pullRequests {
		totalCount
	}
	issues {
		totalCount
	}
	organizations {
		totalCount
	}
	repositoriesContributedTo {
		totalCount
	}
	starredRepositories {
		totalCount
	}

	contributionsCollection {
		totalCommitContributions
		totalPullRequestContributions
		contributionYears
		contributionCalendar {
			totalContributions
		}
	}
`

const graphQLUserFieldsWithoutEmail = `
	name
	login
	location
	bio
	company
	websiteUrl
	twitterUsername
	avatarUrl
	pronouns
	isHireable
	isBountyHunter
	isCampusExpert
	isDeveloperProgramMember
	isGitHubStar
	isSiteAdmin
	isEmployee
	hasSponsorsListing
	createdAt
	updatedAt

	status {
		message
		emoji
	}

	databaseId
	pinnedItemsRemaining

	socialAccounts(first: 10) {
		nodes {
			provider
			url
			displayName
		}
	}

	topRepositories(first: 1, orderBy: {field: STARGAZERS, direction: DESC}) {
		totalCount
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

	gists(first: 5, privacy: PUBLIC, orderBy: {field: CREATED_AT, direction: DESC}) {
		totalCount
		nodes {
			name
			description
			url
			createdAt
		}
	}

	pullRequests {
		totalCount
	}
	issues {
		totalCount
	}
	organizations {
		totalCount
	}
	repositoriesContributedTo {
		totalCount
	}
	starredRepositories {
		totalCount
	}

	contributionsCollection {
		totalCommitContributions
		totalPullRequestContributions
		contributionYears
		contributionCalendar {
			totalContributions
		}
	}
`

// tokenHash returns a short hash of the token for cache keying (avoids storing raw tokens).
func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:8])
}

// hasEmailScope checks if the token has user:email scope via a cheap HEAD request.
// The result is cached per-token for 24 hours.
func (c *Client) hasEmailScope(ctx context.Context) bool {
	if c.token == "" {
		return false
	}

	if c.cache == nil {
		return c.checkTokenScopeHTTP(ctx)
	}

	cacheKey := "github:scope:" + tokenHash(c.token)
	data, err := c.cache.GetSet(ctx, cacheKey, func(ctx context.Context) ([]byte, error) {
		if c.checkTokenScopeHTTP(ctx) {
			return []byte("1"), nil
		}
		return []byte("0"), nil
	}, scopeCacheTTL)
	if err != nil {
		return true // assume yes on error
	}
	return string(data) == "1"
}

// checkTokenScopeHTTP makes the actual HTTP request to check token scopes.
func (c *Client) checkTokenScopeHTTP(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://api.github.com/user", http.NoBody)
	if err != nil {
		return true // assume yes on error, will fail gracefully
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", "sociopath/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.DebugContext(ctx, "scope check request failed", "error", err)
		return true // assume yes on error
	}
	defer resp.Body.Close() //nolint:errcheck // best effort close

	scopes := resp.Header.Get("X-Oauth-Scopes")
	hasScope := strings.Contains(scopes, "user:email") || strings.Contains(scopes, "read:user") || strings.Contains(scopes, "user")
	c.logger.DebugContext(ctx, "checked token scopes", "scopes", scopes, "has_email_scope", hasScope)
	return hasScope
}

func (c *Client) fetchGraphQL(ctx context.Context, urlStr, username string) (*profile.Profile, error) {
	// Check if token has email scope before making the query
	if !c.hasEmailScope(ctx) {
		return c.executeGraphQL(ctx, urlStr, username, graphQLUserFieldsWithoutEmail)
	}

	// Try with email field
	prof, err := c.executeGraphQL(ctx, urlStr, username, graphQLUserFieldsWithEmail)
	if err != nil {
		// Check if error is due to missing email scope (fallback for fine-grained PATs)
		if strings.Contains(err.Error(), "email") || strings.Contains(err.Error(), "scope") {
			c.logger.DebugContext(ctx, "GraphQL email field failed, retrying without email", "error", err)
			// Update cache to remember this token doesn't have email scope
			if c.cache != nil {
				cacheKey := "github:scope:" + tokenHash(c.token)
				//nolint:errcheck,gosec // best effort cache update
				c.cache.GetSet(ctx, cacheKey, func(context.Context) ([]byte, error) {
					return []byte("0"), nil
				}, scopeCacheTTL)
			}
			return c.executeGraphQL(ctx, urlStr, username, graphQLUserFieldsWithoutEmail)
		}
		return nil, err
	}
	return prof, nil
}

func (c *Client) executeGraphQL(ctx context.Context, urlStr, username, fields string) (*profile.Profile, error) {
	start := time.Now()
	query := `query($login: String!) { user(login: $login) { ` + fields + ` } }`

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

	c.logger.DebugContext(ctx, "GraphQL query completed", "username", username, "duration_ms", time.Since(start).Milliseconds())
	return parseGraphQLResponse(ctx, body, urlStr, username, c.logger)
}

// graphQLUser holds the user data from a GraphQL response.
//
//nolint:govet // fieldalignment: intentional layout for readability
type graphQLUser struct {
	Name                     string `json:"name"`
	Login                    string `json:"login"`
	Location                 string `json:"location"`
	Bio                      string `json:"bio"`
	Company                  string `json:"company"`
	Email                    string `json:"email"`
	WebsiteURL               string `json:"websiteUrl"`
	TwitterUser              string `json:"twitterUsername"`
	AvatarURL                string `json:"avatarUrl"`
	Pronouns                 string `json:"pronouns"`
	IsHireable               bool   `json:"isHireable"`
	IsBountyHunter           bool   `json:"isBountyHunter"`
	IsCampusExpert           bool   `json:"isCampusExpert"`
	IsDeveloperProgramMember bool   `json:"isDeveloperProgramMember"`
	IsGitHubStar             bool   `json:"isGitHubStar"`
	IsSiteAdmin              bool   `json:"isSiteAdmin"`
	IsEmployee               bool   `json:"isEmployee"`
	HasSponsorsListing       bool   `json:"hasSponsorsListing"`
	DatabaseID               int    `json:"databaseId"`
	PinnedItemsRemaining     int    `json:"pinnedItemsRemaining"`
	CreatedAt                string `json:"createdAt"`
	UpdatedAt                string `json:"updatedAt"`
	Status                   *struct {
		Message string `json:"message"`
		Emoji   string `json:"emoji"`
	} `json:"status"`
	SocialAccounts struct {
		Nodes []struct {
			URL         string `json:"url"`
			Provider    string `json:"provider"`
			DisplayName string `json:"displayName"`
		} `json:"nodes"`
	} `json:"socialAccounts"`
	TopRepositories           struct{ TotalCount int } `json:"topRepositories"`
	Followers                 struct{ TotalCount int } `json:"followers"`
	Following                 struct{ TotalCount int } `json:"following"`
	Repositories              struct{ TotalCount int } `json:"repositories"`
	PullRequests              struct{ TotalCount int } `json:"pullRequests"`
	Issues                    struct{ TotalCount int } `json:"issues"`
	Organizations             struct{ TotalCount int } `json:"organizations"`
	RepositoriesContributedTo struct{ TotalCount int } `json:"repositoriesContributedTo"`
	StarredRepositories       struct{ TotalCount int } `json:"starredRepositories"`
	Gists                     struct {
		TotalCount int        `json:"totalCount"`
		Nodes      []gistNode `json:"nodes"`
	} `json:"gists"`
	ContributionsCollection struct {
		TotalCommitContributions      int   `json:"totalCommitContributions"`
		TotalPullRequestContributions int   `json:"totalPullRequestContributions"`
		ContributionYears             []int `json:"contributionYears"`
		ContributionCalendar          struct {
			TotalContributions int `json:"totalContributions"`
		} `json:"contributionCalendar"`
	} `json:"contributionsCollection"`
}

// addCountField adds a count field if the value is greater than 0.
func addCountField(fields map[string]string, key string, count int) {
	if count > 0 {
		fields[key] = strconv.Itoa(count)
	}
}

func parseGraphQLResponse(ctx context.Context, data []byte, urlStr, _ string, logger *slog.Logger) (*profile.Profile, error) {
	var response struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
		Data struct {
			User graphQLUser `json:"user"`
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
		prof.Fields["company"] = strings.TrimSpace(strings.TrimPrefix(user.Company, "@"))
	}

	// Add stats
	addCountField(prof.Fields, "public_repos", user.Repositories.TotalCount)
	addCountField(prof.Fields, "followers", user.Followers.TotalCount)
	addCountField(prof.Fields, "following", user.Following.TotalCount)
	addCountField(prof.Fields, "public_gists", user.Gists.TotalCount)
	addCountField(prof.Fields, "pull_requests", user.PullRequests.TotalCount)
	addCountField(prof.Fields, "issues", user.Issues.TotalCount)
	addCountField(prof.Fields, "organizations_count", user.Organizations.TotalCount)
	addCountField(prof.Fields, "repos_contributed_to", user.RepositoriesContributedTo.TotalCount)
	addCountField(prof.Fields, "starred_repos", user.StarredRepositories.TotalCount)
	addCountField(prof.Fields, "top_repos", user.TopRepositories.TotalCount)
	addCountField(prof.Fields, "pinned_items_remaining", user.PinnedItemsRemaining)

	// Database ID (useful for correlation and detecting renames)
	if user.DatabaseID > 0 {
		prof.DatabaseID = strconv.Itoa(user.DatabaseID)
		prof.Fields["database_id"] = prof.DatabaseID
	}

	// Contribution stats (last year)
	cc := user.ContributionsCollection
	addCountField(prof.Fields, "commits_year", cc.TotalCommitContributions)
	addCountField(prof.Fields, "prs_year", cc.TotalPullRequestContributions)
	addCountField(prof.Fields, "total_contributions_year", cc.ContributionCalendar.TotalContributions)

	// Contribution years (account tenure)
	if len(cc.ContributionYears) > 0 {
		prof.Fields["first_contribution_year"] = strconv.Itoa(cc.ContributionYears[len(cc.ContributionYears)-1])
		prof.Fields["contribution_years_count"] = strconv.Itoa(len(cc.ContributionYears))
	}

	if user.Gists.TotalCount > 0 {
		prof.Posts = gistsToPosts(user.Gists.Nodes)
		// Check for keybase proof gists and extract username
		if keybaseURL := extractKeybaseFromGists(ctx, user.Gists.Nodes, user.Login, logger); keybaseURL != "" {
			prof.SocialLinks = append(prof.SocialLinks, keybaseURL)
			logger.InfoContext(ctx, "discovered keybase from gist", "url", keybaseURL)
		}
	}

	// Add Twitter from GraphQL
	if user.TwitterUser != "" {
		twitterURL := "https://twitter.com/" + user.TwitterUser
		prof.Fields["twitter"] = twitterURL
		prof.SocialLinks = append(prof.SocialLinks, twitterURL)
	}

	// Add social accounts from GraphQL
	for _, social := range user.SocialAccounts.Nodes {
		if social.URL != "" {
			prof.SocialLinks = append(prof.SocialLinks, social.URL)
		}
	}

	if user.AvatarURL != "" {
		prof.AvatarURL = user.AvatarURL
	}
	if user.Pronouns != "" {
		prof.Fields["pronouns"] = user.Pronouns
	}
	if user.IsHireable {
		prof.Fields["hireable"] = "true"
	}
	if user.IsBountyHunter {
		prof.Fields["bounty_hunter"] = "true"
	}
	if user.IsCampusExpert {
		prof.Fields["campus_expert"] = "true"
	}
	if user.IsDeveloperProgramMember {
		prof.Fields["developer_program_member"] = "true"
	}
	if user.IsGitHubStar {
		prof.Fields["github_star"] = "true"
	}
	if user.IsSiteAdmin {
		prof.Fields["site_admin"] = "true"
	}
	if user.IsEmployee {
		prof.Fields["github_employee"] = "true"
	}
	if user.HasSponsorsListing {
		prof.Fields["sponsors_listing"] = "true"
	}
	if user.Status != nil && user.Status.Message != "" {
		status := user.Status.Message
		if user.Status.Emoji != "" {
			status = user.Status.Emoji + " " + status
		}
		prof.Fields["status"] = status
	}
	if user.Email != "" {
		prof.Fields["email"] = user.Email
	}
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
	defer resp.Body.Close() //nolint:errcheck // best effort close //nolint:errcheck // error ignored intentionally

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

// extractPinnedRepos extracts pinned/popular repositories from the profile page.
func extractPinnedRepos(htmlContent string) []profile.Repository {
	var repos []profile.Repository

	// Match div with pinned-item-list-item class (GitHub moved this from <li> to inner <div>)
	itemPattern := regexp.MustCompile(`(?s)<div[^>]*class="[^"]*pinned-item-list-item[^"]*"[^>]*>.*?</div>\s*</li>`)
	items := itemPattern.FindAllString(htmlContent, -1)

	linkPattern := regexp.MustCompile(
		`href="(/[^"]+)"[^>]*class="[^"]*Link[^"]*text-bold[^"]*"[^>]*>` +
			`.*?<span class="repo"[^>]*>\s*([^<]+)\s*</span>`)
	descPattern := regexp.MustCompile(`(?s)<p class="pinned-item-desc[^"]*"[^>]*>\s*(.*?)\s*</p>`)
	langPattern := regexp.MustCompile(`itemprop="programmingLanguage">([^<]+)</span>`)
	starsPattern := regexp.MustCompile(`(?s)aria-label="stars"[^>]*>.*?</svg>\s*([^<\s]+)`)
	forksPattern := regexp.MustCompile(`(?s)aria-label="forks"[^>]*>.*?</svg>\s*([^<\s]+)`)

	for _, item := range items {
		linkMatch := linkPattern.FindStringSubmatch(item)
		if len(linkMatch) < 3 {
			continue
		}

		repo := profile.Repository{
			Name: strings.TrimSpace(linkMatch[2]),
			URL:  "https://github.com" + strings.TrimSpace(linkMatch[1]),
		}

		if m := descPattern.FindStringSubmatch(item); len(m) > 1 {
			repo.Description = strings.TrimSpace(m[1])
		}
		if m := langPattern.FindStringSubmatch(item); len(m) > 1 {
			repo.Language = strings.TrimSpace(m[1])
		}
		if m := starsPattern.FindStringSubmatch(item); len(m) > 1 {
			repo.Stars = strings.TrimSpace(m[1])
		}
		if m := forksPattern.FindStringSubmatch(item); len(m) > 1 {
			repo.Forks = strings.TrimSpace(m[1])
		}

		repos = append(repos, repo)
	}

	return repos
}

// extractEmail extracts email address from GitHub profile HTML.
// Email is shown to logged-in users via mailto links.
func extractEmail(html string) string {
	// Pattern: <a ... href="mailto:email@example.com">email@example.com</a>
	mailtoPattern := regexp.MustCompile(`href="mailto:([^"]+)"`)
	if matches := mailtoPattern.FindStringSubmatch(html); len(matches) > 1 {
		return matches[1]
	}
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
		PublicGists int    `json:"public_gists"`
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
	if ghUser.PublicGists > 0 {
		prof.Fields["public_gists"] = strconv.Itoa(ghUser.PublicGists)
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

	// Extract email (visible to authenticated users)
	if email := extractEmail(html); email != "" {
		prof.Fields["email"] = email
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

// UsernameFromEmail looks up a GitHub username from an email address.
// It first searches users with the email, then falls back to searching commits.
// Returns empty string if no username is found.
func (c *Client) UsernameFromEmail(ctx context.Context, email string) string {
	// First, try searching users with email
	if username := c.searchUsersByEmail(ctx, email); username != "" {
		return username
	}

	// Fall back to searching commits by author email
	return c.searchCommitsByEmail(ctx, email)
}

func (c *Client) searchUsersByEmail(ctx context.Context, email string) string {
	searchURL := fmt.Sprintf("https://api.github.com/search/users?q=%s+in:email", email)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, http.NoBody)
	if err != nil {
		c.logger.WarnContext(ctx, "failed to create user search request", "error", err)
		return ""
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "sociopath/1.0")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	body, err := c.doAPIRequest(ctx, req)
	if err != nil {
		c.logger.DebugContext(ctx, "user search failed", "email", email, "error", err)
		return ""
	}

	var result struct {
		Items []struct {
			Login string `json:"login"`
		} `json:"items"`
		TotalCount int `json:"total_count"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		c.logger.WarnContext(ctx, "failed to parse user search response", "error", err)
		return ""
	}

	if result.TotalCount > 0 && len(result.Items) > 0 {
		c.logger.InfoContext(ctx, "found GitHub user by email search",
			"email", email, "username", result.Items[0].Login)
		return result.Items[0].Login
	}

	return ""
}

func (c *Client) searchCommitsByEmail(ctx context.Context, email string) string {
	searchURL := fmt.Sprintf("https://api.github.com/search/commits?q=author-email:%s&sort=author-date&per_page=1", email)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, http.NoBody)
	if err != nil {
		c.logger.WarnContext(ctx, "failed to create commit search request", "error", err)
		return ""
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "sociopath/1.0")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	body, err := c.doAPIRequest(ctx, req)
	if err != nil {
		c.logger.DebugContext(ctx, "commit search failed", "email", email, "error", err)
		return ""
	}

	var result struct {
		Items []struct {
			Author struct {
				Login string `json:"login"`
			} `json:"author"`
		} `json:"items"`
		TotalCount int `json:"total_count"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		c.logger.WarnContext(ctx, "failed to parse commit search response", "error", err)
		return ""
	}

	if result.TotalCount > 0 && len(result.Items) > 0 && result.Items[0].Author.Login != "" {
		c.logger.InfoContext(ctx, "found GitHub user by commit search",
			"email", email, "username", result.Items[0].Author.Login)
		return result.Items[0].Author.Login
	}

	return ""
}

// ghAuthToken returns the GitHub token from the gh CLI, or empty string if unavailable.
func ghAuthToken(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// gistNode represents a gist from the GraphQL response.
type gistNode struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	CreatedAt   string `json:"createdAt"`
}

// gistsToPosts converts gist nodes to profile posts.
func gistsToPosts(gists []gistNode) []profile.Post {
	posts := make([]profile.Post, 0, len(gists))
	for _, g := range gists {
		title := g.Description
		if title == "" {
			title = g.Name
		}
		posts = append(posts, profile.Post{
			Type:    profile.PostTypePost,
			Title:   title,
			Content: g.Description,
			URL:     g.URL,
		})
	}
	return posts
}

// keybaseProofPattern matches keybase.io URLs in gist content.
var keybaseProofPattern = regexp.MustCompile(`https://keybase\.io/([a-zA-Z0-9_]+)`)

// extractKeybaseFromGists looks for keybase proof gists and extracts the username.
func extractKeybaseFromGists(ctx context.Context, gists []gistNode, ghUsername string, logger *slog.Logger) string {
	for _, g := range gists {
		// Check if gist name or description mentions keybase
		nameLower := strings.ToLower(g.Name)
		descLower := strings.ToLower(g.Description)
		if !strings.Contains(nameLower, "keybase") && !strings.Contains(descLower, "keybase") {
			continue
		}

		// Construct raw URL from gist URL
		// gist URL: https://gist.github.com/gistid (GraphQL doesn't include username)
		// raw URL: https://gist.githubusercontent.com/username/gistid/raw
		gistID := strings.TrimPrefix(g.URL, "https://gist.github.com/")
		rawURL := fmt.Sprintf("https://gist.githubusercontent.com/%s/%s/raw", ghUsername, gistID)

		// Fetch raw content
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
		if err != nil {
			logger.DebugContext(ctx, "failed to create keybase gist request", "url", rawURL, "error", err)
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logger.DebugContext(ctx, "failed to fetch keybase gist", "url", rawURL, "error", err)
			continue
		}

		keybaseURL := extractKeybaseFromResponse(resp)
		if keybaseURL != "" {
			return keybaseURL
		}
	}
	return ""
}

// extractKeybaseFromResponse reads the response body and extracts keybase URL.
func extractKeybaseFromResponse(resp *http.Response) string {
	defer resp.Body.Close() //nolint:errcheck // best effort cleanup
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return ""
	}
	if matches := keybaseProofPattern.FindSubmatch(body); len(matches) > 1 {
		return "https://keybase.io/" + string(matches[1])
	}
	return ""
}

// archiveSnapshot represents a snapshot from the Internet Archive CDX API.
type archiveSnapshot struct {
	Timestamp  string // Format: 20251009202051
	StatusCode string // HTTP status code when archived
}

// archiveClient is a dedicated HTTP client for Internet Archive requests with a longer timeout.
var archiveClient = &http.Client{Timeout: 30 * time.Second}

// checkInternetArchive queries the Internet Archive CDX API for snapshots of a GitHub profile.
// Returns the most recent successful snapshot, or nil if none found.
func (c *Client) checkInternetArchive(ctx context.Context, username string) *archiveSnapshot {
	cdxURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=github.com/%s&output=json&limit=10&filter=statuscode:200", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cdxURL, http.NoBody)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to create archive request", "error", err)
		return nil
	}
	req.Header.Set("User-Agent", "sociopath/1.0")

	resp, err := archiveClient.Do(req)
	if err != nil {
		c.logger.DebugContext(ctx, "archive lookup failed", "error", err)
		return nil
	}
	defer resp.Body.Close() //nolint:errcheck // best effort

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil
	}

	// Parse JSON array: [["urlkey","timestamp","original",...], ["row1",...], ...]
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		c.logger.DebugContext(ctx, "failed to parse archive response", "error", err)
		return nil
	}

	// Need at least header row + one data row
	if len(rows) < 2 {
		return nil
	}

	// Find column indices from header
	header := rows[0]
	timestampIdx, statusIdx := -1, -1
	for i, col := range header {
		switch col {
		case "timestamp":
			timestampIdx = i
		case "statuscode":
			statusIdx = i
		default:
			// ignore other columns
		}
	}

	if timestampIdx < 0 {
		return nil
	}

	// Return the most recent snapshot (last row with status 200)
	for i := len(rows) - 1; i >= 1; i-- {
		row := rows[i]
		if statusIdx >= 0 && statusIdx < len(row) && row[statusIdx] != "200" {
			continue
		}
		if timestampIdx < len(row) {
			c.logger.InfoContext(ctx, "found archived profile", "username", username, "timestamp", row[timestampIdx])
			return &archiveSnapshot{
				Timestamp:  row[timestampIdx],
				StatusCode: "200",
			}
		}
	}

	return nil
}

// avatarIDPattern extracts the user database ID from avatar URLs.
var avatarIDPattern = regexp.MustCompile(`avatars\.githubusercontent\.com/u/(\d+)`)

// fetchArchivedProfile fetches and parses a GitHub profile from the Internet Archive.
func (c *Client) fetchArchivedProfile(ctx context.Context, username string, snapshot *archiveSnapshot) *profile.Profile {
	archiveURL := fmt.Sprintf("https://web.archive.org/web/%s/https://github.com/%s", snapshot.Timestamp, username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL, http.NoBody)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to create archive fetch request", "error", err)
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	resp, err := archiveClient.Do(req)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to fetch archived profile", "error", err)
		return nil
	}
	defer resp.Body.Close() //nolint:errcheck // best effort

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}

	html := string(body)
	prof := c.parseProfileFromHTML(ctx, html, "https://github.com/"+username, username)

	// Extract database ID from avatar URL
	if matches := avatarIDPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.DatabaseID = matches[1]
	}

	// Format archived timestamp for display (20251009202051 -> 2025-10-09T20:20:51Z)
	if len(snapshot.Timestamp) >= 14 {
		ts := snapshot.Timestamp
		prof.ArchivedAt = fmt.Sprintf("%s-%s-%sT%s:%s:%sZ",
			ts[0:4], ts[4:6], ts[6:8], ts[8:10], ts[10:12], ts[12:14])
	}

	// Extract additional fields from archived HTML
	if loc := extractArchivedLocation(html); loc != "" && prof.Location == "" {
		prof.Location = loc
	}

	// Extract organizations from archived HTML
	if orgs := extractOrganizations(html); len(orgs) > 0 {
		prof.Fields["organizations"] = strings.Join(orgs, ", ")
	}

	return prof
}

// extractArchivedLocation extracts location from archived profile HTML.
func extractArchivedLocation(html string) string {
	// Matches aria-label="Home location: <location>"
	locPattern := regexp.MustCompile(`aria-label="Home location:\s*([^"]+)"`)
	if matches := locPattern.FindStringSubmatch(html); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// checkUserByID queries GitHub API by database ID to check if user was renamed.
// Returns the current profile if found, nil otherwise.
func (c *Client) checkUserByID(ctx context.Context, databaseID string) (*profile.Profile, error) {
	apiURL := "https://api.github.com/user/" + databaseID

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

	return parseJSON(body, "", "")
}

// handleMissingUser attempts to recover information about a 404'd GitHub user.
// It checks Internet Archive for historical data and detects renames.
func (c *Client) handleMissingUser(ctx context.Context, username, urlStr string) (*profile.Profile, error) {
	// Check Internet Archive for historical snapshots
	snapshot := c.checkInternetArchive(ctx, username)
	if snapshot == nil {
		c.logger.InfoContext(ctx, "no archived profile found", "username", username)
		return nil, fmt.Errorf("user not found and no archive available: %s", username)
	}

	// Fetch archived profile to get database ID
	archivedProf := c.fetchArchivedProfile(ctx, username, snapshot)
	if archivedProf == nil {
		return nil, fmt.Errorf("failed to fetch archived profile for: %s", username)
	}

	// If we have a database ID, check if user was renamed
	if archivedProf.DatabaseID != "" {
		currentProf, err := c.checkUserByID(ctx, archivedProf.DatabaseID)
		if err == nil && currentProf != nil && currentProf.Username != "" {
			// User was renamed - fetch current profile with full data
			c.logger.InfoContext(ctx, "detected username rename",
				"old_username", username,
				"new_username", currentProf.Username,
				"database_id", archivedProf.DatabaseID,
			)

			// Fetch the full current profile
			fullProf, fetchErr := c.Fetch(ctx, "https://github.com/"+currentProf.Username)
			if fetchErr != nil {
				// Fall back to basic data from ID lookup
				c.logger.DebugContext(ctx, "failed to fetch renamed profile, using basic data", "error", fetchErr)
				currentProf.URL = urlStr
				currentProf.AccountState = profile.AccountStateRenamed
				currentProf.Aliases = []string{username}
				currentProf.DatabaseID = archivedProf.DatabaseID
				return currentProf, nil
			}

			fullProf.AccountState = profile.AccountStateRenamed
			fullProf.Aliases = []string{username}
			fullProf.DatabaseID = archivedProf.DatabaseID
			return fullProf, nil
		}
	}

	// User was truly deleted - return archived profile
	c.logger.InfoContext(ctx, "user appears deleted, using archived data",
		"username", username,
		"archived_at", archivedProf.ArchivedAt,
	)

	archivedProf.URL = urlStr
	archivedProf.AccountState = profile.AccountStateDeleted
	return archivedProf, nil
}
