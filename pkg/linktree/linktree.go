// Package linktree fetches Linktree profile data.
package linktree

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

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "linktree"

// Match returns true if the URL is a Linktree profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "linktr.ee/") || strings.Contains(lower, "linktree.com/")
}

// AuthRequired returns false because Linktree profiles are public.
func AuthRequired() bool { return false }

// Client handles Linktree requests.
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

// New creates a Linktree client.
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

// Fetch retrieves a Linktree profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	// Normalize URL
	if !strings.HasPrefix(urlStr, "http") {
		urlStr = "https://linktr.ee/" + username
	}

	c.logger.InfoContext(ctx, "fetching linktree profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(body, urlStr, username), nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Try to extract JSON data from __NEXT_DATA__ script tag
	jsonData := extractNextData(content)
	if jsonData != nil {
		parseNextData(p, jsonData)
	}

	// Fallback: extract from meta tags
	if p.Name == "" {
		p.Name = extractMetaContent(content, "og:title")
		// Clean up title (remove " | Linktree" suffix)
		if idx := strings.Index(p.Name, " | "); idx > 0 {
			p.Name = strings.TrimSpace(p.Name[:idx])
		}
	}

	if p.Bio == "" {
		p.Bio = extractMetaContent(content, "og:description")
	}

	return p
}

func extractNextData(content string) map[string]any {
	// Use (?s) flag to make . match newlines, [^>]* to match extra attributes
	re := regexp.MustCompile(`(?s)<script id="__NEXT_DATA__" type="application/json"[^>]*>(.*?)</script>`)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		var data map[string]any
		if err := json.Unmarshal([]byte(matches[1]), &data); err == nil {
			return data
		}
	}
	return nil
}

func parseNextData(p *profile.Profile, data map[string]any) {
	props, ok := data["props"].(map[string]any)
	if !ok {
		return
	}

	pageProps, ok := props["pageProps"].(map[string]any)
	if !ok {
		return
	}

	parseAccountInfo(p, pageProps)
	parseLinks(p, pageProps)
	parseSocialIcons(p, pageProps)
}

func parseAccountInfo(p *profile.Profile, pageProps map[string]any) {
	account, ok := pageProps["account"].(map[string]any)
	if !ok {
		return
	}
	if username, ok := account["username"].(string); ok {
		p.Username = username
	}
	// Try profileTitle first, then pageTitle
	if profileTitle, ok := account["profileTitle"].(string); ok && profileTitle != "" {
		p.Name = profileTitle
	} else if pageTitle, ok := account["pageTitle"].(string); ok && pageTitle != "" {
		p.Name = strings.TrimPrefix(pageTitle, "@")
	}
	if desc, ok := account["description"].(string); ok {
		p.Bio = desc
	}
	// Extract avatar URL from profilePictureUrl
	if avatarURL, ok := account["profilePictureUrl"].(string); ok && avatarURL != "" {
		p.AvatarURL = avatarURL
	}
}

func parseLinks(p *profile.Profile, pageProps map[string]any) {
	links, ok := pageProps["links"].([]any)
	if !ok {
		return
	}

	for _, link := range links {
		linkMap, ok := link.(map[string]any)
		if !ok {
			continue
		}

		url, urlOk := linkMap["url"].(string)
		if !urlOk || url == "" {
			continue
		}
		title := getStringField(linkMap, "title")
		categorizePrimaryLink(p, url, title)
	}
}

func categorizePrimaryLink(p *profile.Profile, url, title string) {
	lowerURL := strings.ToLower(url)
	lowerTitle := strings.ToLower(title)

	switch {
	case strings.Contains(lowerURL, "twitter.com") || strings.Contains(lowerURL, "x.com"):
		p.Fields["twitter"] = url
		p.SocialLinks = append(p.SocialLinks, url)
	case strings.Contains(lowerURL, "linkedin.com"):
		p.Fields["linkedin"] = url
		p.SocialLinks = append(p.SocialLinks, url)
	case strings.Contains(lowerURL, "github.com"):
		p.Fields["github"] = url
		p.SocialLinks = append(p.SocialLinks, url)
	case strings.Contains(lowerURL, "instagram.com"):
		p.Fields["instagram"] = url
		p.SocialLinks = append(p.SocialLinks, url)
	case strings.Contains(lowerURL, "youtube.com"):
		p.Fields["youtube"] = url
		p.SocialLinks = append(p.SocialLinks, url)
	case strings.Contains(lowerURL, "tiktok.com"):
		p.Fields["tiktok"] = url
		p.SocialLinks = append(p.SocialLinks, url)
	case strings.Contains(lowerURL, "matrix.to") || strings.Contains(lowerURL, "matrix.org"):
		p.Fields["matrix"] = url
		p.SocialLinks = append(p.SocialLinks, url)
	case strings.Contains(lowerURL, "keybase.io"):
		p.Fields["keybase"] = url
		p.SocialLinks = append(p.SocialLinks, url)
	case isMastodonURL(lowerURL):
		p.Fields["mastodon"] = url
		p.SocialLinks = append(p.SocialLinks, url)
	case strings.Contains(lowerTitle, "website") || strings.Contains(lowerTitle, "site"):
		if p.Website == "" {
			p.Website = url
		}
		p.Fields["website"] = url
	case strings.HasPrefix(url, "mailto:"):
		p.Fields["email"] = strings.TrimPrefix(url, "mailto:")
	default:
		// Add any unrecognized external links to SocialLinks
		if !strings.Contains(lowerURL, "linktr.ee") {
			p.SocialLinks = append(p.SocialLinks, url)
		}
	}
}

// isMastodonURL checks if a URL is likely a Mastodon instance.
func isMastodonURL(lowerURL string) bool {
	// Common Mastodon instance patterns
	mastodonPatterns := []string{
		"mastodon.", ".social/@", "infosec.exchange", "hachyderm.io",
		"fosstodon.org", "mstdn.social", "mas.to", "techhub.social",
		"chaos.social", "toot.", "todon.", "masto.",
	}
	for _, pattern := range mastodonPatterns {
		if strings.Contains(lowerURL, pattern) {
			return true
		}
	}
	// Check for /@username pattern which is common on Mastodon
	return strings.Contains(lowerURL, "/@")
}

func parseSocialIcons(p *profile.Profile, pageProps map[string]any) {
	socialLinks, ok := pageProps["socialLinks"].([]any)
	if !ok {
		return
	}

	for _, link := range socialLinks {
		linkMap, ok := link.(map[string]any)
		if !ok {
			continue
		}

		url, urlOk := linkMap["url"].(string)
		if !urlOk || url == "" {
			continue
		}
		linkType := getStringField(linkMap, "type")
		categorizeSocialIcon(p, url, linkType)
	}
}

func getStringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func categorizeSocialIcon(p *profile.Profile, url, linkType string) {
	lowerType := strings.ToLower(linkType)

	switch {
	case strings.Contains(lowerType, "twitter"):
		if p.Fields["twitter"] == "" {
			p.Fields["twitter"] = url
			p.SocialLinks = append(p.SocialLinks, url)
		}
	case strings.Contains(lowerType, "linkedin"):
		if p.Fields["linkedin"] == "" {
			p.Fields["linkedin"] = url
			p.SocialLinks = append(p.SocialLinks, url)
		}
	case strings.Contains(lowerType, "github"):
		if p.Fields["github"] == "" {
			p.Fields["github"] = url
			p.SocialLinks = append(p.SocialLinks, url)
		}
	case strings.Contains(lowerType, "email"):
		if p.Fields["email"] == "" {
			p.Fields["email"] = strings.TrimPrefix(url, "mailto:")
		}
	default:
		p.SocialLinks = append(p.SocialLinks, url)
	}
}

func extractMetaContent(content, property string) string {
	// Try property first
	re := regexp.MustCompile(`<meta[^>]+property="` + regexp.QuoteMeta(property) + `"[^>]+content="([^"]*)"`)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		return matches[1]
	}

	// Try content before property
	re = regexp.MustCompile(`<meta[^>]+content="([^"]*)"[^>]+property="` + regexp.QuoteMeta(property) + `"`)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func extractUsername(urlStr string) string {
	// Handle linktr.ee/username format
	if idx := strings.Index(urlStr, "linktr.ee/"); idx != -1 {
		username := urlStr[idx+len("linktr.ee/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}

	// Handle linktree.com/username format
	if idx := strings.Index(urlStr, "linktree.com/"); idx != -1 {
		username := urlStr[idx+len("linktree.com/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}

	return ""
}
