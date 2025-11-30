// Package mastodon fetches Mastodon user profile data.
package mastodon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/cache"
	"github.com/codeGROOVE-dev/sociopath/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/profile"
)

const platform = "mastodon"

// Known Mastodon instances.
var knownInstances = map[string]bool{
	"mastodon.social": true, "mastodon.online": true, "fosstodon.org": true,
	"hachyderm.io": true, "infosec.exchange": true, "techhub.social": true,
	"mstdn.social": true, "mas.to": true, "mastodon.world": true,
	"ruby.social": true, "phpc.social": true, "chaos.social": true,
	"octodon.social": true, "social.coop": true, "sfba.social": true,
}

// Match returns true if the URL is a Mastodon profile URL.
func Match(urlStr string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	host := strings.ToLower(parsed.Host)

	// Check known instances
	if knownInstances[host] {
		return strings.HasPrefix(parsed.Path, "/@") || strings.HasPrefix(parsed.Path, "/users/")
	}

	// Check for .social TLD with /@username pattern
	if strings.HasSuffix(host, ".social") && strings.HasPrefix(parsed.Path, "/@") {
		return true
	}

	// Generic /@username pattern (heuristic)
	if strings.HasPrefix(parsed.Path, "/@") && len(parsed.Path) > 2 {
		return true
	}

	return false
}

// AuthRequired returns false because Mastodon profiles are public.
func AuthRequired() bool { return false }

// Client handles Mastodon requests.
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

// New creates a Mastodon client.
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

// Fetch retrieves a Mastodon profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	username := extractUsername(parsed.Path)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching mastodon profile", "url", urlStr, "username", username)

	// Try API first
	p, err := c.fetchViaAPI(ctx, parsed.Host, username)
	if err == nil {
		p.URL = urlStr
		return p, nil
	}

	c.logger.Debug("API fetch failed, falling back to HTML", "error", err)

	// Fallback to HTML scraping
	return c.fetchViaHTML(ctx, urlStr, username)
}

func (c *Client) fetchViaAPI(ctx context.Context, host, username string) (*profile.Profile, error) {
	apiURL := fmt.Sprintf("https://%s/api/v1/accounts/lookup?acct=%s", host, username)

	// Check cache
	if c.cache != nil {
		if data, _, _, found := c.cache.Get(ctx, apiURL); found {
			return c.parseAPIResponse(data)
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

	return c.parseAPIResponse(body)
}

func (*Client) parseAPIResponse(data []byte) (*profile.Profile, error) {
	var acc struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Note        string `json:"note"`
		CreatedAt   string `json:"created_at"`
		Fields      []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"fields"`
	}

	if err := json.Unmarshal(data, &acc); err != nil {
		return nil, err
	}

	p := &profile.Profile{
		Platform:      platform,
		Authenticated: false,
		Username:      acc.Username,
		Name:          acc.DisplayName,
		Bio:           stripHTML(acc.Note),
		Fields:        make(map[string]string),
	}

	// Extract fields and look for location
	for _, f := range acc.Fields {
		name := stripHTML(f.Name)
		value := stripHTML(f.Value)
		p.Fields[name] = value

		lower := strings.ToLower(name)
		if strings.Contains(lower, "location") || strings.Contains(lower, "city") ||
			strings.Contains(lower, "country") || strings.Contains(lower, "place") {
			p.Location = value
		}

		// Extract website URLs
		if urls := extractURLs(f.Value); len(urls) > 0 {
			p.SocialLinks = append(p.SocialLinks, urls...)
		}
	}

	// Filter out same-server Mastodon links
	p.SocialLinks = filterSameServerLinks(p.SocialLinks, p.URL)

	return p, nil
}

func (c *Client) fetchViaHTML(ctx context.Context, urlStr, username string) (*profile.Profile, error) {
	// Check cache
	if c.cache != nil {
		if data, _, _, found := c.cache.Get(ctx, urlStr); found {
			return c.parseHTML(data, urlStr, username), nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
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
		_ = c.cache.SetAsync(ctx, urlStr, body, "", nil) //nolint:errcheck // async, error ignored
	}

	return c.parseHTML(body, urlStr, username), nil
}

func (*Client) parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Extract bio from meta description
	p.Bio = htmlutil.Description(content)
	p.Name = htmlutil.Title(content)
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Filter out same-server Mastodon links
	p.SocialLinks = filterSameServerLinks(p.SocialLinks, urlStr)

	return p
}

func extractUsername(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "@") {
			return strings.TrimPrefix(part, "@")
		}
	}
	if len(parts) >= 2 && parts[0] == "users" {
		return parts[1]
	}
	return ""
}

func stripHTML(s string) string {
	s = html.UnescapeString(s)
	s = strings.ReplaceAll(s, "<br>", "\n")
	s = strings.ReplaceAll(s, "<br/>", "\n")
	s = strings.ReplaceAll(s, "</p>", "\n")
	re := regexp.MustCompile(`<[^>]+>`)
	return strings.TrimSpace(re.ReplaceAllString(s, ""))
}

func extractURLs(htmlContent string) []string {
	re := regexp.MustCompile(`href=["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(htmlContent, -1)
	var urls []string
	for _, m := range matches {
		if len(m) > 1 && strings.HasPrefix(m[1], "http") {
			urls = append(urls, m[1])
		}
	}
	return urls
}

func filterSameServerLinks(links []string, profileURL string) []string {
	// Extract the server/host from the profile URL
	parsed, err := url.Parse(profileURL)
	if err != nil {
		return links
	}
	profileHost := strings.ToLower(parsed.Host)

	var filtered []string
	for _, link := range links {
		linkParsed, err := url.Parse(link)
		if err != nil {
			filtered = append(filtered, link)
			continue
		}
		linkHost := strings.ToLower(linkParsed.Host)

		// If it's a Mastodon link on the same server, filter it out
		if Match(link) && linkHost == profileHost {
			continue
		}

		filtered = append(filtered, link)
	}
	return filtered
}
