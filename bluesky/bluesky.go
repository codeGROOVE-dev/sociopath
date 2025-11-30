// Package bluesky fetches BlueSky user profile data.
package bluesky

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/profile"
)

const platform = "bluesky"

// Match returns true if the URL is a BlueSky profile URL.
func Match(urlStr string) bool {
	return strings.Contains(strings.ToLower(urlStr), "bsky.app/profile/")
}

// AuthRequired returns false because BlueSky profiles are public.
func AuthRequired() bool { return false }

// Client handles BlueSky requests.
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

// New creates a BlueSky client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves a BlueSky profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	handle := extractHandle(urlStr)
	if handle == "" {
		return nil, fmt.Errorf("could not extract handle from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching bluesky profile", "url", urlStr, "handle", handle)

	apiURL := fmt.Sprintf("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=%s", handle)

	// Check cache
	if c.cache != nil {
		if data, _, _, found := c.cache.Get(ctx, apiURL); found {
			return parseAPIResponse(data, urlStr, handle)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sociopath/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // error ignored intentionally

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	// Cache response (async, errors intentionally ignored)
	if c.cache != nil {
		_ = c.cache.SetAsync(ctx, apiURL, body, "", nil) //nolint:errcheck // async, error ignored
	}

	return parseAPIResponse(body, urlStr, handle)
}

func parseAPIResponse(data []byte, urlStr, handle string) (*profile.Profile, error) {
	var resp struct {
		Handle      string `json:"handle"`
		DisplayName string `json:"displayName"`
		Description string `json:"description"`
		CreatedAt   string `json:"createdAt"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      handle,
		Name:          resp.DisplayName,
		Bio:           resp.Description,
		Fields:        make(map[string]string),
	}

	if resp.CreatedAt != "" {
		p.Fields["joined"] = resp.CreatedAt
	}

	// Extract hashtags from bio
	if resp.Description != "" {
		re := regexp.MustCompile(`#(\w+)`)
		p.Fields["hashtags"] = strings.Join(re.FindAllString(resp.Description, -1), ", ")
	}

	return p, nil
}

func extractHandle(urlStr string) string {
	if idx := strings.Index(urlStr, "bsky.app/profile/"); idx != -1 {
		handle := urlStr[idx+len("bsky.app/profile/"):]
		handle = strings.Split(handle, "/")[0]
		handle = strings.Split(handle, "?")[0]
		return strings.TrimSpace(handle)
	}
	return ""
}
