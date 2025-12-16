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
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
)

// LinkedInCacheTTL is the cache duration for LinkedIn profile data (180 days).
// LinkedIn profiles change infrequently, so long caching is appropriate.
const LinkedInCacheTTL = 180 * 24 * time.Hour

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
		return b.parseResults(data)
	}

	data, err := b.doSearch(ctx, query)
	if err != nil {
		return nil, err
	}
	return b.parseResults(data)
}

// doSearch performs the actual API call.
func (b *BraveSearcher) doSearch(ctx context.Context, query string) ([]byte, error) {
	endpoint := "https://api.search.brave.com/res/v1/web/search"

	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint: %w", err)
	}

	q := u.Query()
	q.Set("q", query)
	q.Set("count", "10")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Subscription-Token", b.apiKey)

	if b.logger != nil {
		b.logger.DebugContext(ctx, "brave search", "query", query)
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best effort cleanup

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if err != nil {
			return nil, fmt.Errorf("brave API returned %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("brave API returned %d: %s", resp.StatusCode, string(body))
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
