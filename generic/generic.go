// Package generic provides HTML fallback extraction for unknown social media platforms.
package generic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/profile"
)

const platform = "generic"

// Match always returns true as this is the fallback.
func Match(_ string) bool { return true }

// AuthRequired returns false.
func AuthRequired() bool { return false }

// Client handles generic website requests.
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

// New creates a generic client.
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

// Fetch retrieves content from a generic website and converts to markdown.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	// Normalize URL
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}

	// Security: validate URL
	if err := validateURL(urlStr); err != nil {
		return nil, err
	}

	c.logger.InfoContext(ctx, "fetching generic website", "url", urlStr)

	// Check cache
	if c.cache != nil {
		if data, _, _, found := c.cache.Get(ctx, urlStr); found {
			return parseHTML(data, urlStr), nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

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

	return parseHTML(body, urlStr), nil
}

func parseHTML(data []byte, urlStr string) *profile.Profile {
	content := string(data)

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Fields:        make(map[string]string),
	}

	p.Name = htmlutil.Title(content)
	p.Bio = htmlutil.Description(content)
	p.Unstructured = htmlutil.ToMarkdown(content)

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Also extract contact/about page links for recursion
	contactLinks := htmlutil.ContactLinks(content, urlStr)
	p.SocialLinks = append(p.SocialLinks, contactLinks...)

	// Deduplicate social links
	p.SocialLinks = dedupeLinks(p.SocialLinks)

	// Extract emails
	emails := htmlutil.EmailAddresses(content)
	if len(emails) > 0 {
		p.Fields["email"] = emails[0] // Primary email
		if len(emails) > 1 {
			// Store additional emails
			for i, email := range emails[1:] {
				p.Fields[fmt.Sprintf("email_%d", i+2)] = email
			}
		}
	}

	return p
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

// validateURL checks for SSRF vulnerabilities.
func validateURL(urlStr string) error {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	host := strings.ToLower(parsed.Hostname())

	// Block localhost and local domains
	if host == "localhost" || host == "127.0.0.1" || host == "::1" ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return errors.New("blocked: local host")
	}

	// Block private IP ranges
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return errors.New("blocked: private IP")
		}
	}

	// Block metadata service endpoints
	if host == "169.254.169.254" || host == "metadata.google.internal" || host == "metadata.azure.com" {
		return errors.New("blocked: metadata service")
	}

	return nil
}
