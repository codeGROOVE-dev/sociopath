package linkedin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
)

// LinkedInCacheTTL is the cache duration for LinkedIn profile data (90 days).
const LinkedInCacheTTL = 90 * 24 * time.Hour

// BraveSearcher implements Searcher using the Brave Search API.
// Free tier: 2,000 queries/month, 1 query/second.
// Get an API key at https://api.search.brave.com/
type BraveSearcher struct {
	httpClient *http.Client
	cache      httpcache.Cacher
	logger     *slog.Logger
	apiKey     string
}

// braveResponse represents the Brave Search API response.
type braveResponse struct {
	Web struct {
		Results []struct {
			Title       string `json:"title"`
			URL         string `json:"url"`
			Description string `json:"description"`
		} `json:"results"`
	} `json:"web"`
}

// BraveOption configures a BraveSearcher.
type BraveOption func(*BraveSearcher)

// WithBraveCache sets a cache for storing search results.
func WithBraveCache(cache httpcache.Cacher) BraveOption {
	return func(b *BraveSearcher) { b.cache = cache }
}

// WithBraveLogger sets a logger for the searcher.
func WithBraveLogger(logger *slog.Logger) BraveOption {
	return func(b *BraveSearcher) { b.logger = logger }
}

// NewBraveSearcher creates a new Brave Search API client.
// apiKey is your Brave Search API subscription token.
func NewBraveSearcher(apiKey string, opts ...BraveOption) *BraveSearcher {
	b := &BraveSearcher{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// LoadBraveAPIKey loads the Brave API key from multiple sources (in priority order):
// 1. BRAVE_API_KEY environment variable
// 2. ~/.brave file (first line, trimmed)
//
// Returns empty string if no key is found.
func LoadBraveAPIKey() string {
	// 1. Check environment variable
	if key := os.Getenv("BRAVE_API_KEY"); key != "" {
		return key
	}

	// 2. Check ~/.brave file
	if home, err := os.UserHomeDir(); err == nil {
		braveFile := filepath.Join(home, ".brave")
		if data, err := os.ReadFile(braveFile); err == nil {
			if key := strings.TrimSpace(string(data)); key != "" {
				return key
			}
		}
	}

	return ""
}

// Search performs a web search using the Brave Search API.
func (b *BraveSearcher) Search(ctx context.Context, query string) ([]SearchResult, error) {
	// Use cache if available
	if b.cache != nil {
		cacheKey := "brave:" + httpcache.URLToKey(query)
		data, err := b.cache.GetSet(ctx, cacheKey, func(ctx context.Context) ([]byte, error) {
			return b.doSearch(ctx, query)
		}, LinkedInCacheTTL)
		if err != nil {
			return nil, err
		}
		if err := checkCachedError(data); err != nil {
			return nil, err
		}
		return b.parseResults(data)
	}

	data, err := b.doSearch(ctx, query)
	if err != nil {
		return nil, err
	}
	if err := checkCachedError(data); err != nil {
		return nil, err
	}
	return b.parseResults(data)
}

// checkCachedError checks if data contains a cached error marker.
func checkCachedError(data []byte) error {
	s := string(data)
	if errCode, found := strings.CutPrefix(s, "ERROR:"); found {
		return fmt.Errorf("brave API returned %s", errCode)
	}
	if errMsg, found := strings.CutPrefix(s, "NETERR:"); found {
		return fmt.Errorf("network error: %s", errMsg)
	}
	return nil
}

// doSearch performs the actual API call, returning error markers for caching.
func (b *BraveSearcher) doSearch(ctx context.Context, query string) ([]byte, error) {
	endpoint := "https://api.search.brave.com/res/v1/web/search"

	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Appendf(nil, "NETERR:%s", err.Error()), nil
	}

	q := u.Query()
	q.Set("q", query)
	q.Set("count", "10")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return fmt.Appendf(nil, "NETERR:%s", err.Error()), nil
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Subscription-Token", b.apiKey)

	if b.logger != nil {
		b.logger.DebugContext(ctx, "brave search", "query", query)
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return fmt.Appendf(nil, "NETERR:%s", err.Error()), nil
	}
	defer resp.Body.Close() //nolint:errcheck // best effort cleanup

	if resp.StatusCode != http.StatusOK {
		return fmt.Appendf(nil, "ERROR:%d", resp.StatusCode), nil
	}

	return io.ReadAll(resp.Body)
}

// parseResults converts the raw JSON response to SearchResult slice.
func (*BraveSearcher) parseResults(data []byte) ([]SearchResult, error) {
	var br braveResponse
	if err := json.Unmarshal(data, &br); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	results := make([]SearchResult, 0, len(br.Web.Results))
	for _, r := range br.Web.Results {
		results = append(results, SearchResult{
			Title:   r.Title,
			URL:     r.URL,
			Snippet: r.Description,
		})
	}

	return results, nil
}

// ProfileSearchResult represents location and profile data found via search.
type ProfileSearchResult struct {
	Query       string  `json:"query,omitempty"`
	ProfileURL  string  `json:"profile_url,omitempty"`
	Name        string  `json:"name,omitempty"`
	Headline    string  `json:"headline,omitempty"`
	JobTitle    string  `json:"job_title,omitempty"`
	Company     string  `json:"company,omitempty"`
	Location    string  `json:"location,omitempty"`
	Education   string  `json:"education,omitempty"`
	Connections string  `json:"connections,omitempty"`
	Bio         string  `json:"bio,omitempty"`
	Confidence  float64 `json:"confidence"`
}

// Location patterns for extracting location from search results.
var searchLocationPatterns = []*regexp.Regexp{
	// LinkedIn "Location: X" format (most reliable for LinkedIn snippets)
	regexp.MustCompile(`(?i)Location:\s*([A-Za-z][A-Za-z\s,]+?)(?:\s*·|\s*$|\.)`),
	// City, State format (US)
	regexp.MustCompile(`(?i)\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*),\s*([A-Z]{2})\b`),
	// "Greater X Area" format (LinkedIn style)
	regexp.MustCompile(`(?i)Greater\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+Area`),
	// "X Metropolitan Area" format
	regexp.MustCompile(`(?i)([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+Metropolitan\s+Area`),
	// "Based in X" format
	regexp.MustCompile(`(?i)(?:based|located|living)\s+in\s+([A-Z][a-z]+(?:[,\s]+[A-Z][a-z]+)*)`),
	// Country names
	regexp.MustCompile(`(?i)\b(United States|Canada|United Kingdom|Australia|Germany|France|India|Japan|Brazil|Netherlands|Singapore|Israel)\b`),
}

// bioStrongPattern extracts text between <strong> tags (LinkedIn bio snippet).
var bioStrongPattern = regexp.MustCompile(`<strong>([^<]+)</strong>`)

// SearchByName searches for a LinkedIn profile by name and employment info.
// This is useful when you have GitHub profile data with name/employer but no LinkedIn URL.
// Returns nil if no profile is found or if there's insufficient data to search.
func (b *BraveSearcher) SearchByName(ctx context.Context, name, employer, jobTitle string) (*ProfileSearchResult, error) {
	if name == "" {
		return nil, nil //nolint:nilnil // nil means no search performed
	}
	if employer == "" && jobTitle == "" {
		return nil, nil //nolint:nilnil // need at least employer or job title
	}

	query := buildSearchQuery(name, employer, jobTitle)
	if query == "" {
		return nil, nil //nolint:nilnil // no query could be built
	}

	if b.logger != nil {
		b.logger.InfoContext(ctx, "linkedin search by name", "query", query)
	}

	results, err := b.Search(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}

	// Log raw results
	if b.logger != nil {
		for i, r := range results {
			b.logger.InfoContext(ctx, "brave search result",
				"index", i,
				"title", r.Title,
				"url", r.URL)
		}
	}

	result := parseProfileResults(results, employer, b.logger)
	result.Query = query

	if b.logger != nil {
		b.logger.Info("linkedin search result",
			"profile_url", result.ProfileURL,
			"name", result.Name,
			"location", result.Location,
			"headline", result.Headline,
			"confidence", result.Confidence)
	}

	if b.logger != nil {
		if result.Location != "" {
			b.logger.InfoContext(ctx, "linkedin search found location",
				"query", query, "location", result.Location, "confidence", result.Confidence)
		} else {
			b.logger.DebugContext(ctx, "linkedin search found no location", "query", query)
		}
	}

	return result, nil
}

// buildSearchQuery constructs a search query for LinkedIn profile.
func buildSearchQuery(name, employer, jobTitle string) string {
	parts := []string{name}

	if jobTitle != "" {
		parts = append(parts, jobTitle)
	}

	if employer != "" {
		parts = append(parts, employer)
	}

	parts = append(parts, "linkedin")

	return strings.Join(parts, " ")
}

// parseProfileResults extracts all available data from LinkedIn search results.
// searchCompany is the company we searched for - used to verify matches.
//
//nolint:gocognit // two-pass parsing with clear structure
func parseProfileResults(results []SearchResult, searchCompany string, logger *slog.Logger) *ProfileSearchResult {
	result := &ProfileSearchResult{}
	searchCompanyNorm := normalizeCompanyForMatch(searchCompany)

	if logger != nil {
		logger.Info("parsing linkedin results",
			"result_count", len(results),
			"search_company", searchCompany,
			"normalized_company", searchCompanyNorm)
	}

	// First pass: find the primary LinkedIn profile result
	for i := range results {
		r := &results[i]
		// Only consider LinkedIn profile URLs (not posts, company pages, etc.)
		if !strings.Contains(r.URL, "linkedin.com/in/") {
			continue
		}

		result.ProfileURL = r.URL

		// Extract name and company from title: "Name - Company | LinkedIn"
		if result.Name == "" {
			result.Name, result.Company = parseLinkedInTitle(r.Title)
		}

		// Parse LinkedIn snippet format: "Headline · Experience: X · Education: Y · Location: Z · N connections"
		// Skip generic LinkedIn descriptions that aren't actual profile data
		if !isGenericLinkedInSnippet(r.Snippet) {
			parseLinkedInSnippet(r.Snippet, result)
		}

		// Extract location from title or description using patterns
		text := r.Title + " " + r.Snippet
		textLower := strings.ToLower(text)

		if result.Location == "" {
			for _, pattern := range searchLocationPatterns {
				m := pattern.FindStringSubmatch(text)
				if len(m) > 1 {
					loc := m[1]
					if len(m) > 2 && m[2] != "" {
						loc = m[1] + ", " + m[2]
					}
					result.Location = strings.TrimSpace(loc)
					break
				}
			}
		}

		// Set confidence based on company match (any of the search terms)
		if result.Location != "" {
			if containsAnySearchTerm(textLower, searchCompanyNorm) {
				result.Confidence = 0.9
			} else {
				result.Confidence = 0.7
			}
		}

		// Extract bio from <strong> tags if not already set
		if result.Bio == "" {
			result.Bio = extractBioFromSnippet(r.Snippet)
		}

		// If we found a location from the primary profile, we're done with this result
		if result.Location != "" {
			break
		}
	}

	// Second pass: look for additional job title info from other results
	// Only consider results that mention the company we searched for
	if result.JobTitle == "" && searchCompanyNorm != "" {
		for i := range results {
			r := &results[i]
			// Look in all LinkedIn results for job titles
			if !strings.Contains(r.URL, "linkedin.com") {
				continue
			}
			snippetLower := strings.ToLower(r.Snippet)
			// Only extract job title from results that mention any of the search terms
			if !containsAnySearchTerm(snippetLower, searchCompanyNorm) {
				if logger != nil {
					logger.Info("skipping result for job title - company not found",
						"index", i,
						"url", r.URL,
						"looking_for", searchCompanyNorm)
				}
				continue
			}
			if title := extractDetailedJobTitle(r.Snippet); title != "" {
				if logger != nil {
					logger.Info("found job title from result",
						"index", i,
						"job_title", title)
				}
				result.JobTitle = title
				break
			}
		}
	}

	// If we found a profile URL but no location, still return with lower confidence
	if result.ProfileURL != "" && result.Confidence == 0 {
		result.Confidence = 0.5
	}

	return result
}

// parseLinkedInTitle extracts name and company from LinkedIn title format.
// Format: "Name - Company | LinkedIn" or "Name - Headline | LinkedIn".
func parseLinkedInTitle(title string) (name, company string) {
	// Remove " | LinkedIn" suffix
	title = strings.TrimSuffix(title, " | LinkedIn")
	title = strings.TrimSuffix(title, " - LinkedIn")
	title = strings.TrimSpace(title)

	// Split on " - "
	parts := strings.SplitN(title, " - ", 2)
	if len(parts) >= 1 {
		name = strings.TrimSpace(parts[0])
	}
	if len(parts) >= 2 {
		company = strings.TrimSpace(parts[1])
	}
	return name, company
}

// parseLinkedInSnippet extracts structured data from LinkedIn snippet.
// Format: "Headline · Experience: Company · Education: School · Location: Place · N connections".
func parseLinkedInSnippet(snippet string, result *ProfileSearchResult) {
	// Split by LinkedIn's separator
	parts := strings.Split(snippet, " · ")

	for i, part := range parts {
		part = strings.TrimSpace(part)

		// First part before any ":" is usually the headline/tagline
		if i == 0 && !strings.Contains(part, ":") && result.Headline == "" {
			// Clean up the headline
			headline := strings.TrimSuffix(part, ".")
			if headline != "" && len(headline) < 200 {
				result.Headline = headline
			}
			continue
		}

		// Parse "Key: Value" format
		if idx := strings.Index(part, ": "); idx > 0 {
			key := strings.ToLower(part[:idx])
			value := strings.TrimSpace(part[idx+2:])

			switch key {
			case "experience":
				if result.Company == "" {
					result.Company = value
				}
			case "education":
				if result.Education == "" {
					result.Education = value
				}
			case "location":
				if result.Location == "" {
					result.Location = value
				}
			default:
				// Ignore other keys
			}
			continue
		}

		// Check for connections pattern: "500+ connections on LinkedIn"
		if strings.Contains(strings.ToLower(part), "connection") {
			if m := regexp.MustCompile(`(\d+\+?)\s*connections?`).FindStringSubmatch(part); len(m) > 1 {
				if result.Connections == "" {
					result.Connections = m[1]
				}
			}
		}
	}
}

// extractDetailedJobTitle looks for detailed job titles in snippets.
// Looks for patterns like "Vice President, Delivery" or "Senior Software Engineer".
func extractDetailedJobTitle(snippet string) string {
	// First try to extract from <strong> tags (most reliable)
	strongPattern := regexp.MustCompile(`<strong>([^<]+)</strong>`)
	for _, m := range strongPattern.FindAllStringSubmatch(snippet, -1) {
		if len(m) > 1 {
			title := strings.TrimSpace(m[1])
			// Check if it looks like a job title
			titleLower := strings.ToLower(title)
			if strings.Contains(titleLower, "president") ||
				strings.Contains(titleLower, "director") ||
				strings.Contains(titleLower, "manager") ||
				strings.Contains(titleLower, "engineer") ||
				strings.Contains(titleLower, "lead") ||
				strings.Contains(titleLower, "head") ||
				strings.Contains(titleLower, "chief") ||
				strings.Contains(titleLower, "founder") ||
				strings.Contains(titleLower, "cto") ||
				strings.Contains(titleLower, "ceo") {
				// Clean up
				title = strings.TrimRight(title, " ·,.-")
				if len(title) > 5 && len(title) < 100 {
					return title
				}
			}
		}
	}

	// Patterns for job titles in plain text
	patterns := []*regexp.Regexp{
		// "Vice President, X" or "VP of X"
		regexp.MustCompile(`(?i)\b((?:Senior |Executive |Associate )?Vice President(?:,| of)? [A-Za-z]+(?:\s+[A-Za-z]+)?)`),
		// "Director of X" or "Senior Director"
		regexp.MustCompile(`(?i)\b((?:Senior |Managing |Executive )?Director(?:,| of)? [A-Za-z]+(?:\s+[A-Za-z]+)?)`),
		// "Head of X"
		regexp.MustCompile(`(?i)\b(Head of [A-Za-z]+(?:\s+[A-Za-z]+)?)`),
		// "Chief X Officer"
		regexp.MustCompile(`(?i)\b(Chief [A-Za-z]+ Officer)\b`),
		// "Senior/Staff/Principal Engineer/Developer"
		regexp.MustCompile(`(?i)\b((?:Senior |Staff |Principal |Lead |Distinguished )?` +
			`(?:Software |Platform |DevOps |Site Reliability |Security )?` +
			`(?:Engineer|Developer|Architect))\b`),
	}

	for _, p := range patterns {
		if m := p.FindStringSubmatch(snippet); len(m) > 1 {
			title := strings.TrimSpace(m[1])
			title = strings.TrimRight(title, " ·,.-")
			if len(title) > 5 && len(title) < 100 {
				return title
			}
		}
	}

	return ""
}

// extractBioFromSnippet extracts bio text from LinkedIn search snippet.
// LinkedIn often puts the bio text in <strong> tags in the search snippet.
func extractBioFromSnippet(snippet string) string {
	all := bioStrongPattern.FindAllStringSubmatch(snippet, -1)
	if len(all) == 0 {
		return ""
	}

	// Concatenate all <strong> content (may be split across multiple tags)
	var parts []string
	for _, m := range all {
		if len(m) > 1 && m[1] != "" {
			parts = append(parts, m[1])
		}
	}

	if len(parts) == 0 {
		return ""
	}

	// Join parts and clean up
	bio := strings.Join(parts, " ")
	bio = strings.TrimSuffix(bio, "…")
	bio = strings.TrimSuffix(bio, "...")
	return strings.TrimSpace(bio)
}

// normalizeCompanyForMatch normalizes a company name for fuzzy matching.
// Extracts @mention if present, strips common suffixes like -dev, -inc, etc.
// Returns space-separated normalized terms if input contains multiple words.
func normalizeCompanyForMatch(company string) string {
	if company == "" {
		return ""
	}

	s := strings.ToLower(company)

	// If there's an @mention, extract just that part (e.g., "Field CTO @edera-dev" -> "edera-dev")
	if idx := strings.Index(s, "@"); idx >= 0 {
		// Extract from @ to end or next space
		rest := s[idx+1:]
		if spaceIdx := strings.IndexAny(rest, " \t"); spaceIdx >= 0 {
			s = rest[:spaceIdx]
		} else {
			s = rest
		}
	}

	// Strip common GitHub org suffixes from each word
	words := strings.Fields(s)
	for i, w := range words {
		for _, suf := range []string{"-dev", "-inc", "-io", "-hq", "-oss", "-labs", "-team", ".io", ".dev", ".com"} {
			w = strings.TrimSuffix(w, suf)
		}
		words[i] = w
	}

	return strings.Join(words, " ")
}

// isGenericLinkedInSnippet returns true if the snippet is generic LinkedIn boilerplate.
func isGenericLinkedInSnippet(snippet string) bool {
	genericPhrases := []string{
		"billion members",
		"manage your professional identity",
		"build and engage with your professional network",
		"access knowledge, insights and opportunities",
		"join linkedin today",
		"see who you know",
	}
	lower := strings.ToLower(snippet)
	for _, phrase := range genericPhrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// containsAnySearchTerm checks if text contains any of the search terms.
// Also tries matching with spaces removed to handle "defenseunicorns" vs "defense unicorns".
func containsAnySearchTerm(textLower, searchTerms string) bool {
	if searchTerms == "" {
		return false
	}
	// Also check text with spaces removed for compound matches
	textNoSpaces := strings.ReplaceAll(textLower, " ", "")
	for term := range strings.FieldsSeq(searchTerms) {
		if strings.Contains(textLower, term) || strings.Contains(textNoSpaces, term) {
			return true
		}
	}
	return false
}
