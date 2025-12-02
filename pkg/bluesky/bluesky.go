// Package bluesky fetches BlueSky user profile data.
package bluesky

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/cache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
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
	cache      cache.HTTPCache
	logger     *slog.Logger
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache  cache.HTTPCache
	logger *slog.Logger
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache cache.HTTPCache) Option {
	return func(c *config) { c.cache = httpCache }
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sociopath/1.0")

	body, err := cache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	p, err := parseAPIResponse(body, urlStr, handle)
	if err != nil {
		return nil, err
	}

	// Fetch recent posts
	posts, lastActive := c.fetchPosts(ctx, handle, 5)
	p.Posts = posts
	if lastActive != "" {
		p.LastActive = lastActive
	}

	return p, nil
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

func (c *Client) fetchPosts(ctx context.Context, handle string, limit int) (posts []profile.Post, lastActive string) {
	apiURL := fmt.Sprintf("https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?actor=%s&limit=%d", handle, limit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sociopath/1.0")

	body, err := cache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, ""
	}

	var feed struct {
		Feed []struct {
			Post struct {
				Author struct {
					Handle string `json:"handle"`
				} `json:"author"`
				Record struct {
					Text      string `json:"text"`
					CreatedAt string `json:"createdAt"`
				} `json:"record"`
			} `json:"post"`
		} `json:"feed"`
	}

	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, ""
	}

	for _, item := range feed.Feed {
		// Only include posts authored by this user (skip reposts)
		if item.Post.Author.Handle != handle {
			continue
		}
		text := strings.TrimSpace(item.Post.Record.Text)
		if text == "" {
			continue
		}
		posts = append(posts, profile.Post{
			Type:    profile.PostTypePost,
			Content: text,
		})
		// First post from this user is the most recent
		if lastActive == "" && item.Post.Record.CreatedAt != "" {
			lastActive = item.Post.Record.CreatedAt
		}
	}

	return posts, lastActive
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
