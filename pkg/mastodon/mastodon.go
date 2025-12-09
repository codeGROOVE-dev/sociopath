// Package mastodon fetches Mastodon user profile data.
package mastodon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
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
	cache      httpcache.Cacher
	logger     *slog.Logger
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache  httpcache.Cacher
	logger *slog.Logger
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache httpcache.Cacher) Option {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sociopath/1.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	p, accountID, err := c.parseAPIResponse(body)
	if err != nil {
		return nil, err
	}

	// Fetch recent posts if we have an account ID
	if accountID != "" {
		posts, lastActive := c.fetchStatuses(ctx, host, accountID, 50)
		p.Posts = posts
		if lastActive != "" && lastActive > p.UpdatedAt {
			p.UpdatedAt = lastActive
		}
	}

	return p, nil
}

func (*Client) parseAPIResponse(data []byte) (*profile.Profile, string, error) {
	var acc struct {
		ID          string `json:"id"`
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
		return nil, "", err
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

	// Add account creation date
	if acc.CreatedAt != "" {
		p.CreatedAt = acc.CreatedAt
	}

	return p, acc.ID, nil
}

func (c *Client) fetchViaHTML(ctx context.Context, urlStr, username string) (*profile.Profile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
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

func (c *Client) fetchStatuses(ctx context.Context, host, accountID string, limit int) (posts []profile.Post, lastActive string) {
	apiURL := fmt.Sprintf("https://%s/api/v1/accounts/%s/statuses?limit=%d&exclude_replies=true&exclude_reblogs=true",
		host, accountID, limit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, ""
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sociopath/1.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, ""
	}

	var statuses []struct {
		Content   string `json:"content"`
		CreatedAt string `json:"created_at"`
	}

	if err := json.Unmarshal(body, &statuses); err != nil {
		return nil, ""
	}

	for i, s := range statuses {
		text := stripHTML(s.Content)
		if text == "" {
			continue
		}
		posts = append(posts, profile.Post{
			Type:    profile.PostTypePost,
			Content: text,
		})
		// First status is the most recent
		if i == 0 && s.CreatedAt != "" {
			lastActive = s.CreatedAt
		}
	}

	return posts, lastActive
}

func extractUsername(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for _, part := range parts {
		if username, found := strings.CutPrefix(part, "@"); found {
			return username
		}
	}
	if len(parts) >= 2 && parts[0] == "users" {
		return parts[1]
	}
	return ""
}

func stripHTML(s string) string {
	s = html.UnescapeString(s)
	// Replace common block-level tags with newlines
	s = strings.ReplaceAll(s, "<br>", "\n")
	s = strings.ReplaceAll(s, "<br/>", "\n")
	s = strings.ReplaceAll(s, "<br />", "\n")
	s = strings.ReplaceAll(s, "</p>", "\n")
	s = strings.ReplaceAll(s, "</div>", "\n")

	// Remove all other HTML tags
	re := regexp.MustCompile(`<[^>]+>`)
	s = re.ReplaceAllString(s, "")

	// Normalize whitespace: replace multiple newlines with single newlines,
	// but preserve intentional line breaks by converting to spaces
	lines := strings.Split(s, "\n")
	var cleaned []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			cleaned = append(cleaned, line)
		}
	}

	// Join with newlines to preserve paragraph structure
	return strings.Join(cleaned, "\n")
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
	parsed, err := url.Parse(profileURL)
	if err != nil {
		return links
	}
	host := parsed.Host

	var out []string
	for _, link := range links {
		u, err := url.Parse(link)
		if err != nil {
			out = append(out, link)
			continue
		}
		// Skip Mastodon links on the same server
		if Match(link) && strings.EqualFold(u.Host, host) {
			continue
		}
		out = append(out, link)
	}
	return out
}
