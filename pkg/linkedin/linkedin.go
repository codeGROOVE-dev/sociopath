// Package linkedin fetches LinkedIn user profile data via web search.
//
// Since LinkedIn blocks direct scraping, this package uses web search engines
// to extract profile data from search result snippets. When a Searcher is
// configured, it searches for the LinkedIn URL and parses the results to
// extract name, headline, company, and location.
//
// Without a Searcher configured, it returns minimal profiles with just the
// URL and username for manual verification.
package linkedin

import (
	"context"
	"log/slog"
	"regexp"
	"strings"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "linkedin"

// SearchResult represents a single web search result.
type SearchResult struct {
	Title   string // Page title (e.g., "Dan Lorenc - Chainguard, Inc | LinkedIn")
	URL     string // Result URL
	Snippet string // Text snippet from search results
}

// Searcher performs web searches. Implementations should search the given
// query and return results. The query will be a LinkedIn profile URL.
type Searcher interface {
	Search(ctx context.Context, query string) ([]SearchResult, error)
}

// platformInfo implements profile.Platform for LinkedIn.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a LinkedIn profile URL.
func Match(urlStr string) bool {
	return strings.Contains(strings.ToLower(urlStr), "linkedin.com/in/")
}

// AuthRequired returns true because LinkedIn requires authentication for direct access.
// When a Searcher is configured, we can still extract data via search results.
func AuthRequired() bool { return true }

// Client handles LinkedIn requests.
type Client struct {
	logger   *slog.Logger
	searcher Searcher
}

// Option configures a Client.
type Option func(*config)

type config struct {
	logger         *slog.Logger
	searcher       Searcher
	cookies        map[string]string
	browserCookies bool
}

// WithCookies sets explicit cookie values (currently unused - auth is broken).
func WithCookies(cookies map[string]string) Option {
	return func(c *config) { c.cookies = cookies }
}

// WithHTTPCache sets the HTTP cache (currently unused - auth is broken).
func WithHTTPCache(_ httpcache.Cacher) Option {
	return func(_ *config) {}
}

// WithBrowserCookies enables reading cookies from browser stores (currently unused - auth is broken).
func WithBrowserCookies() Option {
	return func(c *config) { c.browserCookies = true }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// WithSearcher sets a web search backend for extracting profile data.
// When configured, Fetch will search for the LinkedIn URL and parse
// the results to extract name, headline, company, and location.
func WithSearcher(s Searcher) Option {
	return func(c *config) { c.searcher = s }
}

// New creates a LinkedIn client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.searcher == nil {
		cfg.logger.Debug("linkedin: no searcher configured, will return minimal profiles")
	}

	return &Client{
		logger:   cfg.logger,
		searcher: cfg.searcher,
	}, nil
}

// Fetch retrieves a LinkedIn profile.
// If a Searcher is configured, it searches for the profile URL and extracts
// data from the search results. Otherwise, returns a minimal profile with
// just the URL and username.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	// Normalize URL
	if !strings.HasPrefix(urlStr, "http") {
		urlStr = "https://www.linkedin.com/in/" + urlStr
	}

	username := extractPublicID(urlStr)

	// Try search-based extraction if searcher is configured
	if c.searcher != nil {
		p, err := c.fetchViaSearch(ctx, urlStr, username)
		if err != nil {
			c.logger.WarnContext(ctx, "linkedin search failed, returning minimal profile",
				"url", urlStr, "error", err)
		} else if p != nil {
			return p, nil
		}
	}

	c.logger.DebugContext(ctx, "linkedin: returning minimal profile", "url", urlStr, "username", username)

	// Return minimal profile with just the URL
	return &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}, nil
}

// fetchViaSearch searches for the LinkedIn URL and parses the results.
func (c *Client) fetchViaSearch(ctx context.Context, urlStr, username string) (*profile.Profile, error) {
	results, err := c.searcher.Search(ctx, urlStr)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		c.logger.DebugContext(ctx, "linkedin: no search results", "url", urlStr)
		return &profile.Profile{
			Platform: platform,
			URL:      urlStr,
			Username: username,
			Fields:   make(map[string]string),
		}, nil
	}

	// Find the primary profile result that matches our target URL.
	// We must verify the username matches to avoid returning a different person's profile.
	var primaryResult *SearchResult
	for i := range results {
		r := &results[i]
		if isDirectProfileURL(r.URL) && strings.EqualFold(extractPublicID(r.URL), username) {
			primaryResult = r
			break
		}
	}

	if primaryResult == nil {
		c.logger.DebugContext(ctx, "linkedin: no matching profile URL in results", "url", urlStr)
		return &profile.Profile{
			Platform:     platform,
			URL:          urlStr,
			Username:     username,
			AccountState: profile.AccountStateUnverified,
			Fields:       make(map[string]string),
		}, nil
	}

	// Parse name and headline from title
	name, headline := parseTitle(primaryResult.Title)

	p := &profile.Profile{
		Platform:    platform,
		URL:         urlStr,
		Username:    username,
		DisplayName: name,
		Bio:         headline,
		Fields:      make(map[string]string),
	}

	// Store headline separately in fields
	if headline != "" {
		p.Fields["headline"] = headline
	}

	// Extract company from headline
	if company := extractCompany(headline); company != "" {
		p.Fields["company"] = company
	}

	// Parse additional data from snippet
	if loc := extractLocation(primaryResult.Snippet); loc != "" {
		p.Location = loc
	}

	if edu := extractEducation(primaryResult.Snippet); edu != "" {
		p.Fields["education"] = edu
	}

	if conns := extractConnections(primaryResult.Snippet); conns != "" {
		p.Fields["connections"] = conns
	}

	c.logger.InfoContext(ctx, "linkedin: extracted profile via search",
		"url", urlStr,
		"name", name,
		"headline", headline,
		"location", p.Location)

	return p, nil
}

// EnableDebug enables debug logging (currently a no-op).
func (*Client) EnableDebug() {}

// extractPublicID extracts the username from a LinkedIn profile URL.
func extractPublicID(urlStr string) string {
	re := regexp.MustCompile(`linkedin\.com/in/([^/?]+)`)
	matches := re.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return strings.TrimSuffix(matches[1], "/")
	}
	return ""
}

// isDirectProfileURL returns true if the URL is a direct profile page.
func isDirectProfileURL(url string) bool {
	// Match linkedin.com/in/username but not /posts, /activity, etc.
	re := regexp.MustCompile(`linkedin\.com/in/[^/?]+/?$`)
	return re.MatchString(url)
}

// parseTitle extracts name and headline from a LinkedIn search result title.
// Format: "Name - Headline | LinkedIn" or "Name - Company | LinkedIn".
func parseTitle(title string) (name, headline string) {
	// Remove common suffixes
	title = strings.TrimSuffix(title, " | LinkedIn")
	title = strings.TrimSuffix(title, " - LinkedIn")
	title = strings.TrimSpace(title)

	// Split on " - " to separate name from headline
	parts := strings.SplitN(title, " - ", 2)
	if len(parts) >= 1 {
		name = strings.TrimSpace(parts[0])
	}
	if len(parts) >= 2 {
		headline = strings.TrimSpace(parts[1])
	}
	return name, headline
}

// extractCompany attempts to extract company name from headline.
func extractCompany(headline string) string {
	if headline == "" {
		return ""
	}

	// Common patterns in headlines:
	// "CEO at Company"
	// "Software Engineer @ Company"
	// "Title, Company"
	// "Company" (just company name)
	patterns := []string{
		`(?i)(?:at|@)\s+([^,.|]+)`,
		`(?i)(?:CEO|CTO|CFO|COO|Founder|Director|VP|President)[,\s]+([^,.|]+)`,
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p)
		if m := re.FindStringSubmatch(headline); len(m) > 1 {
			return strings.TrimSpace(m[1])
		}
	}

	// If headline is short and doesn't contain typical title words,
	// it's likely just the company name
	if len(headline) < 50 && !strings.Contains(headline, " - ") &&
		!strings.Contains(headline, " at ") && !strings.Contains(headline, " @ ") {
		return headline
	}

	return ""
}

// Major cities for location extraction.
var majorCities = []string{
	"San Francisco", "New York", "Los Angeles", "Seattle", "Portland",
	"Austin", "Denver", "Chicago", "Boston", "Miami", "Atlanta",
	"Dallas", "Phoenix", "Philadelphia", "Houston", "Detroit",
	"Minneapolis", "Toronto", "Vancouver", "London", "Berlin",
	"Paris", "Amsterdam", "Tokyo", "Singapore", "Sydney", "Melbourne",
}

// extractLocation looks for location patterns in snippet text.
func extractLocation(snippet string) string {
	if snippet == "" {
		return ""
	}

	lower := strings.ToLower(snippet)

	// Look for location patterns
	type locPattern struct {
		re     *regexp.Regexp
		prefix string
	}
	patterns := []locPattern{
		{regexp.MustCompile(`(?i)based in ([^,.]+)`), "based in "},
		{regexp.MustCompile(`(?i)located in ([^,.]+)`), "located in "},
		{regexp.MustCompile(`(?i)location[:\s]+([^,.]+)`), "location: "},
	}

	for _, p := range patterns {
		if p.prefix != "" && !strings.Contains(lower, p.prefix) {
			continue
		}
		if m := p.re.FindStringSubmatch(snippet); len(m) > 1 {
			return strings.TrimSpace(m[1])
		}
	}

	// Try to match major cities
	cityPattern := `(?i)(?:from|in)\s+((?:` + strings.Join(majorCities, "|") + `)[^,.]*)`
	re := regexp.MustCompile(cityPattern)
	if m := re.FindStringSubmatch(snippet); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}

	return ""
}

// extractEducation looks for education patterns in snippet text.
func extractEducation(snippet string) string {
	if snippet == "" {
		return ""
	}

	patterns := []string{
		`(?i)graduate of ([^,.]+)`,
		`(?i)graduated from ([^,.]+)`,
		`(?i)studied at ([^,.]+)`,
		`(?i)attended ([^,.]+(?:University|College|Institute|School)[^,.]*)`,
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p)
		if m := re.FindStringSubmatch(snippet); len(m) > 1 {
			return strings.TrimSpace(m[1])
		}
	}

	return ""
}

// extractConnections looks for connection count in snippet.
func extractConnections(snippet string) string {
	re := regexp.MustCompile(`(\d+)\+?\s*connections?`)
	if m := re.FindStringSubmatch(strings.ToLower(snippet)); len(m) > 1 {
		return m[1]
	}
	return ""
}
