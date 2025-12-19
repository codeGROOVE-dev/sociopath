// Package eksisozluk fetches Ekşi Sözlük (eksisozluk.com) profile data.
// Ekşi Sözlük is a Turkish collaborative dictionary and social platform similar to Reddit/Habr.
package eksisozluk

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "eksisozluk"

// platformInfo implements profile.Platform for Ekşi Sözlük.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is an Ekşi Sözlük profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "eksisozluk.com/") {
		return false
	}
	// Profile URLs are eksisozluk.com/biri/username
	return strings.Contains(lower, "/biri/")
}

// AuthRequired returns false because Ekşi Sözlük profiles are public.
func AuthRequired() bool { return false }

// Client handles Ekşi Sözlük requests.
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

// New creates an Ekşi Sözlük client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves an Ekşi Sözlük profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching eksisozluk profile", "url", urlStr, "username", username)

	// Normalize to /biri/username format
	profileURL := fmt.Sprintf("https://eksisozluk.com/biri/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, profileURL, username)
}

// parseProfile extracts profile data from Ekşi Sözlük HTML.
func parseProfile(data []byte, urlStr, username string) (*profile.Profile, error) {
	content := string(data)

	// Check if profile exists
	if strings.Contains(content, "kullanıcı bulunamadı") || strings.Contains(content, "user not found") {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Display name is typically the username on Ekşi Sözlük
	p.DisplayName = username

	// Extract avatar from img.ekstat.com
	// Format: https://img.ekstat.com/profiles/username-timestamp.jpg
	avatarRe := regexp.MustCompile(`https?://img\.ekstat\.com/profiles/` + regexp.QuoteMeta(username) + `-\d+\.(?:jpg|png|gif)`)
	if m := avatarRe.FindString(content); m != "" {
		p.AvatarURL = m
	}

	// Alternative avatar pattern (in img tags)
	if p.AvatarURL == "" {
		avatarRe2 := regexp.MustCompile(`<img[^>]+src="(https?://img\.ekstat\.com/profiles/[^"]+)"`)
		if m := avatarRe2.FindStringSubmatch(content); len(m) > 1 {
			p.AvatarURL = m[1]
		}
	}

	// Extract entry statistics
	// Total entries
	totalEntriesRe := regexp.MustCompile(`"total_entry["\s:]+(\d+)`)
	if m := totalEntriesRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["total_entries"] = m[1]
	}

	// Last month entries
	lastMonthRe := regexp.MustCompile(`"last_month["\s:]+(\d+)`)
	if m := lastMonthRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["entries_last_month"] = m[1]
	}

	// Last week entries
	lastWeekRe := regexp.MustCompile(`"last_week["\s:]+(\d+)`)
	if m := lastWeekRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["entries_last_week"] = m[1]
	}

	// Today's entries
	todayRe := regexp.MustCompile(`"today["\s:]+(\d+)`)
	if m := todayRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["entries_today"] = m[1]
	}

	// Extract badges
	badgesRe := regexp.MustCompile(`"badges":\s*\[([^\]]+)\]`)
	if m := badgesRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["badges"] = strings.TrimSpace(m[1])
	}

	// Extract social links from content
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract recent entries/posts
	p.Posts = extractPosts(content)

	return p, nil
}

// extractPosts extracts recent entries from the profile page.
func extractPosts(content string) []profile.Post {
	var posts []profile.Post

	// Ekşi Sözlük entries are in <div class="content"> or <li> elements
	// Try to find entry content and URLs
	entryRe := regexp.MustCompile(`<a[^>]+href="([^"]*entry/\d+)"[^>]*>.*?</a>[\s\S]*?<div[^>]*class="[^"]*content[^"]*"[^>]*>([\s\S]*?)</div>`)
	matches := entryRe.FindAllStringSubmatch(content, 20)

	for _, m := range matches {
		if len(m) > 2 {
			url := m[1]
			if !strings.HasPrefix(url, "http") {
				url = "https://eksisozluk.com" + url
			}

			// Clean up content - remove HTML tags and trim
			postContent := m[2]
			postContent = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(postContent, " ")
			postContent = strings.TrimSpace(postContent)

			// Take first 200 chars as excerpt
			if len(postContent) > 200 {
				postContent = postContent[:200] + "..."
			}

			posts = append(posts, profile.Post{
				Type:    profile.PostTypeComment,
				Content: postContent,
				URL:     url,
			})
		}
	}

	// Alternative pattern: look for entry list items
	if len(posts) == 0 {
		entryRe2 := regexp.MustCompile(`<li[^>]*id="entry-item-\d+"[^>]*>[\s\S]*?<div[^>]*class="[^"]*content[^"]*"[^>]*>([\s\S]*?)</div>`)
		matches2 := entryRe2.FindAllStringSubmatch(content, 20)

		for _, m := range matches2 {
			if len(m) > 1 {
				postContent := m[1]
				postContent = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(postContent, " ")
				postContent = strings.TrimSpace(postContent)

				if len(postContent) > 200 {
					postContent = postContent[:200] + "..."
				}

				posts = append(posts, profile.Post{
					Type:    profile.PostTypeComment,
					Content: postContent,
				})
			}
		}
	}

	return posts
}

// extractUsername extracts username from Ekşi Sözlük URL.
func extractUsername(urlStr string) string {
	// Handle eksisozluk.com/biri/username
	if idx := strings.Index(urlStr, "/biri/"); idx != -1 {
		username := urlStr[idx+len("/biri/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}

	return ""
}
