// Package threads provides Threads (Meta) profile fetching via web scraping.
package threads

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "threads"

// platformInfo implements profile.Platform for Threads.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeMicroblog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return false }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Threads profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "threads.net/") && !strings.Contains(lower, "threads.com/") {
		return false
	}
	username := extractUsername(urlStr)
	return username != ""
}

var usernamePattern = regexp.MustCompile(`(?i)threads\.(?:net|com)/@([a-zA-Z0-9_.]+)`)

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) < 2 {
		return ""
	}
	username := matches[1]

	// Skip non-profile paths
	systemPaths := map[string]bool{
		"about": true, "legal": true, "privacy": true,
		"terms": true, "api": true, "explore": true,
		"t": true, // thread URLs
	}
	if systemPaths[strings.ToLower(username)] {
		return ""
	}

	return username
}

// Client handles Threads requests.
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

// New creates a Threads client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves a Threads profile by scraping the web page.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching threads profile", "url", urlStr, "username", username)

	// Normalize to threads.com (threads.net redirects to threads.com)
	profileURL := fmt.Sprintf("https://www.threads.com/@%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Set headers to mimic a real browser
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, fmt.Errorf("fetch threads page: %w", err)
	}

	return c.parseResponse(body, profileURL, username)
}

func (c *Client) parseResponse(data []byte, profileURL, username string) (*profile.Profile, error) {
	content := string(data)

	// Try to extract from meta tags first (more reliable than parsing complex JSON)
	p := c.extractFromMetaTags(content, profileURL, username)
	if p != nil {
		return p, nil
	}

	// Try JSON extraction as fallback
	jsonData := extractScriptJSON(content)
	if jsonData == "" {
		c.logger.Debug("failed to find JSON data in page", "url", profileURL)
		return c.buildBasicProfile(content, profileURL, username), nil
	}

	c.logger.Debug("found embedded JSON", "length", len(jsonData))

	var pageData map[string]any
	if err := json.Unmarshal([]byte(jsonData), &pageData); err != nil {
		c.logger.Debug("failed to parse JSON", "error", err)
		return c.buildBasicProfile(content, profileURL, username), nil
	}

	// Navigate the JSON structure to find user data
	userData, err := extractUserData(pageData)
	if err != nil {
		c.logger.Debug("failed to extract user data from JSON", "error", err)
		return c.buildBasicProfile(content, profileURL, username), nil
	}

	return c.buildProfile(userData, profileURL, username)
}

var scriptJSONPattern = regexp.MustCompile(`(?s)<script[^>]*type="application/json"[^>]*data-sjs[^>]*>(.*?)</script>`)

func extractScriptJSON(content string) string {
	matches := scriptJSONPattern.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func extractUserData(data map[string]any) (map[string]any, error) {
	// Try to navigate through the typical Threads JSON structure
	// The structure can vary, so we'll try multiple paths

	// Path 1: require array
	if require, ok := data["require"].([]any); ok {
		for _, item := range require {
			if arr, ok := item.([]any); ok {
				for _, subItem := range arr {
					if subArr, ok := subItem.([]any); ok {
						for _, elem := range subArr {
							if elemMap, ok := elem.(map[string]any); ok {
								if user := findUserInMap(elemMap); user != nil {
									return user, nil
								}
							}
						}
					}
					if subMap, ok := subItem.(map[string]any); ok {
						if user := findUserInMap(subMap); user != nil {
							return user, nil
						}
					}
				}
			}
		}
	}

	return nil, errors.New("user data not found in JSON structure")
}

func findUserInMap(data map[string]any) map[string]any {
	// Recursively search for user data fields
	if username, ok := data["username"].(string); ok && username != "" {
		// Found a user object
		return data
	}

	// Check for nested structures
	for _, value := range data {
		switch v := value.(type) {
		case map[string]any:
			if user := findUserInMap(v); user != nil {
				return user
			}
		case []any:
			for _, item := range v {
				if itemMap, ok := item.(map[string]any); ok {
					if user := findUserInMap(itemMap); user != nil {
						return user
					}
				}
			}
		}
	}

	return nil
}

func (c *Client) extractFromMetaTags(content, profileURL, username string) *profile.Profile {
	// Extract data from meta tags
	titleRe := regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
	descRe := regexp.MustCompile(`<meta[^>]*name="description"[^>]*content="([^"]+)"`)
	ogImageRe := regexp.MustCompile(`<meta[^>]*property="og:image"[^>]*content="([^"]+)"`)
	ogTitleRe := regexp.MustCompile(`<meta[^>]*property="og:title"[^>]*content="([^"]+)"`)

	var pageTitle, description, avatarURL, ogTitle string

	if matches := titleRe.FindStringSubmatch(content); len(matches) > 1 {
		pageTitle = html.UnescapeString(matches[1])
	}
	if matches := descRe.FindStringSubmatch(content); len(matches) > 1 {
		description = html.UnescapeString(matches[1])
	}
	if matches := ogImageRe.FindStringSubmatch(content); len(matches) > 1 {
		avatarURL = matches[1]
	}
	if matches := ogTitleRe.FindStringSubmatch(content); len(matches) > 1 {
		ogTitle = html.UnescapeString(matches[1])
	}

	// If we have minimal data, return a basic profile
	if pageTitle == "" && description == "" {
		return nil
	}

	p := &profile.Profile{
		Platform:  platform,
		URL:       profileURL,
		Username:  username,
		PageTitle: pageTitle,
		Fields:    make(map[string]string),
	}

	// Extract display name from og:title or page title
	// Format is usually: "Name (@username) • Threads"
	if ogTitle != "" {
		// Extract name from "Name (@username)" pattern
		nameRe := regexp.MustCompile(`^([^(]+)\s*\(@` + username + `\)`)
		if matches := nameRe.FindStringSubmatch(ogTitle); len(matches) > 1 {
			p.DisplayName = strings.TrimSpace(matches[1])
		}
	}

	// Description often contains bio and follower counts
	if description != "" {
		// Format: "52 Followers • 0 Threads • Bio text..."
		p.Bio = description

		// Try to extract follower/thread counts
		followerRe := regexp.MustCompile(`(\d+)\s+Followers?`)
		threadRe := regexp.MustCompile(`(\d+)\s+Threads?`)

		if matches := followerRe.FindStringSubmatch(description); len(matches) > 1 {
			p.Fields["followers"] = matches[1]
		}
		if matches := threadRe.FindStringSubmatch(description); len(matches) > 1 {
			p.Fields["threads_count"] = matches[1]
		}
	}

	if avatarURL != "" {
		p.AvatarURL = avatarURL
	}

	c.logger.Debug("extracted threads profile from meta tags",
		"username", p.Username,
		"name", p.DisplayName,
		"has_bio", p.Bio != "",
	)

	return p
}

func (c *Client) buildBasicProfile(content, profileURL, username string) *profile.Profile {
	p := c.extractFromMetaTags(content, profileURL, username)
	if p != nil {
		return p
	}

	// Absolute fallback
	return &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: username,
		Fields:   make(map[string]string),
	}
}

func (c *Client) buildProfile(user map[string]any, profileURL, username string) (*profile.Profile, error) {
	prof := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract display name
	if fullName, ok := user["full_name"].(string); ok {
		prof.DisplayName = fullName
	}

	// Extract bio/biography
	if bio, ok := user["biography"].(string); ok {
		prof.Bio = bio
	} else if bio, ok := user["bio"].(string); ok {
		prof.Bio = bio
	}

	// Extract avatar URL
	if profilePicURL, ok := user["profile_pic_url"].(string); ok {
		prof.AvatarURL = profilePicURL
	} else if hdProfilePic, ok := user["hd_profile_pic_url_info"].(map[string]any); ok {
		if url, ok := hdProfilePic["url"].(string); ok {
			prof.AvatarURL = url
		}
	}

	// Extract ID
	if id, ok := user["id"].(string); ok {
		prof.DatabaseID = id
	} else {
		switch pk := user["pk"].(type) {
		case string:
			prof.DatabaseID = pk
		case float64:
			prof.DatabaseID = strconv.FormatFloat(pk, 'f', 0, 64)
		}
	}

	// Extract follower/following counts
	if followerCount, ok := user["follower_count"].(float64); ok {
		prof.Fields["followers"] = strconv.Itoa(int(followerCount))
	}
	if followingCount, ok := user["following_count"].(float64); ok {
		prof.Fields["following"] = strconv.Itoa(int(followingCount))
	}

	// Extract verification status
	if isVerified, ok := user["is_verified"].(bool); ok && isVerified {
		prof.Fields["verified"] = "true"
	}

	// Extract website/external URL
	if externalURL, ok := user["external_url"].(string); ok && externalURL != "" {
		prof.Website = externalURL
	}

	// Extract bio links
	if bioLinks, ok := user["bio_links"].([]any); ok {
		for _, link := range bioLinks {
			if linkMap, ok := link.(map[string]any); ok {
				if url, ok := linkMap["url"].(string); ok && url != "" {
					prof.SocialLinks = append(prof.SocialLinks, url)
				}
			}
		}
	}

	// Extract private status
	if isPrivate, ok := user["is_private"].(bool); ok && isPrivate {
		prof.Fields["private"] = "true"
	}

	c.logger.Debug("parsed threads profile",
		"username", prof.Username,
		"name", prof.DisplayName,
		"followers", prof.Fields["followers"],
	)

	return prof, nil
}
