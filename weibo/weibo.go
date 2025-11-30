// Package weibo fetches Weibo (微博) profile data.
package weibo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/auth"
	"github.com/codeGROOVE-dev/sociopath/cache"
	"github.com/codeGROOVE-dev/sociopath/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/profile"
)

const platform = "weibo"

// Match returns true if the URL is a Weibo profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return (strings.Contains(lower, "weibo.com/") || strings.Contains(lower, "weibo.cn/")) &&
		(strings.Contains(lower, "/u/") || regexp.MustCompile(`weibo\.(com|cn)/\d+`).MatchString(lower) ||
			regexp.MustCompile(`weibo\.(com|cn)/[a-z0-9_-]+`).MatchString(lower))
}

// AuthRequired returns false because Weibo profiles are public (but cookies help with bot detection).
func AuthRequired() bool { return false }

// Client handles Weibo requests.
type Client struct {
	httpClient *http.Client
	cache      cache.HTTPCache
	logger     *slog.Logger
	cookies    map[string]string
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache   cache.HTTPCache
	logger  *slog.Logger
	cookies map[string]string
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache cache.HTTPCache) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// WithCookies sets explicit cookie values.
func WithCookies(cookies map[string]string) Option {
	return func(c *config) { c.cookies = cookies }
}

// New creates a Weibo client.
// Cookies are optional but help bypass bot detection.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	// Try to get cookies but don't fail if not available
	var sources []auth.Source
	if len(cfg.cookies) > 0 {
		sources = append(sources, auth.NewStaticSource(cfg.cookies))
	}
	sources = append(sources, auth.EnvSource{}, auth.NewBrowserSource(cfg.logger))

	cookies, _ := auth.ChainSources(ctx, platform, sources...) //nolint:errcheck // cookies are optional

	if len(cookies) > 0 {
		cfg.logger.Info("weibo client created with cookies")
	} else {
		cfg.logger.Info("weibo client created without cookies (may encounter bot detection)")
	}

	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
		cookies:    cookies,
	}, nil
}

// weiboAPIResponse represents the JSON response from Weibo's API.
type weiboAPIResponse struct { //nolint:govet // fieldalignment: struct alignment is fine for readability
	Ok   int `json:"ok"`
	Data struct {
		User struct { //nolint:govet // fieldalignment: struct alignment is fine for readability
			ID              int64  `json:"id"`
			ScreenName      string `json:"screen_name"`
			ProfileImageURL string `json:"profile_image_url"`
			Description     string `json:"description"`
			Location        string `json:"location"`
			FollowersCount  int    `json:"followers_count"`
			FriendsCount    int    `json:"friends_count"`
			StatusesCount   int    `json:"statuses_count"`
			Verified        bool   `json:"verified"`
			VerifiedReason  string `json:"verified_reason"`
		} `json:"user"`
	} `json:"data"`
}

// Fetch retrieves a Weibo profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	normalizedURL := fmt.Sprintf("https://weibo.com/%s", username)
	c.logger.InfoContext(ctx, "fetching weibo profile", "url", normalizedURL, "username", username)

	// Try JSON API first
	apiURL := fmt.Sprintf("https://weibo.com/ajax/profile/info?custom=%s", username)

	// Check cache
	var content []byte
	if c.cache != nil {
		if data, _, _, found := c.cache.Get(ctx, apiURL); found {
			content = data
		}
	}

	if len(content) == 0 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
		if err != nil {
			return nil, err
		}

		// Set headers from the working curl example
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
		req.Header.Set("Accept", "application/json, text/plain, */*")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.Header.Set("Referer", normalizedURL)

		// Add cookies if available
		if len(c.cookies) > 0 {
			var cookieParts []string
			for k, v := range c.cookies {
				cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", k, v))
			}
			req.Header.Set("Cookie", strings.Join(cookieParts, "; "))

			// Add XSRF token header if available
			if xsrf, ok := c.cookies["XSRF-TOKEN"]; ok {
				req.Header.Set("X-Xsrf-Token", xsrf)
			}
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }() //nolint:errcheck // error ignored intentionally

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5MB limit
		if err != nil {
			return nil, err
		}
		content = body

		// Cache response
		if c.cache != nil {
			_ = c.cache.SetAsync(ctx, apiURL, body, "", nil) //nolint:errcheck // error ignored intentionally
		}
	}

	// Try to parse as JSON first
	var apiResp weiboAPIResponse
	if err := json.Unmarshal(content, &apiResp); err == nil && apiResp.Ok == 1 {
		return parseAPIResponse(&apiResp, normalizedURL, username), nil
	}

	// Fallback to HTML parsing (in case API fails or returns HTML)
	html := string(content)

	// Check for bot detection
	if strings.Contains(html, "Sina Visitor System") ||
		strings.Contains(html, "访问页面") { //nolint:gosmopolitan // Chinese text is intentional for Weibo
		return nil, errors.New("weibo bot detection triggered - try using browser cookies")
	}

	return parseHTMLProfile(html, normalizedURL)
}

// parseAPIResponse parses the JSON API response.
func parseAPIResponse(apiResp *weiboAPIResponse, url, username string) *profile.Profile {
	user := &apiResp.Data.User
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Name:     user.ScreenName,
		Bio:      user.Description,
		Location: user.Location,
		Fields:   make(map[string]string),
	}

	// Add counts as fields
	if user.FollowersCount > 0 {
		prof.Fields["followers"] = strconv.Itoa(user.FollowersCount)
	}
	if user.FriendsCount > 0 {
		prof.Fields["following"] = strconv.Itoa(user.FriendsCount)
	}
	if user.StatusesCount > 0 {
		prof.Fields["posts"] = strconv.Itoa(user.StatusesCount)
	}

	// Add verification status
	if user.Verified && user.VerifiedReason != "" {
		prof.Fields["verified"] = user.VerifiedReason
	}

	return prof
}

// parseHTMLProfile parses HTML content (fallback when API doesn't work).
func parseHTMLProfile(html, url string) (*profile.Profile, error) { //nolint:unparam // error return part of interface pattern
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: extractUsername(url),
		Fields:   make(map[string]string),
	}

	// Extract name from title or meta tags
	prof.Name = htmlutil.Title(html)
	if prof.Name != "" {
		// Clean up "Name的微博_微博" or similar
		prof.Name = strings.TrimSuffix(prof.Name, "的微博_微博") //nolint:gosmopolitan // Chinese text is intentional for Weibo
		prof.Name = strings.TrimSuffix(prof.Name, "的微博")    //nolint:gosmopolitan // Chinese text is intentional for Weibo
		prof.Name = strings.TrimSuffix(prof.Name, "_微博")    //nolint:gosmopolitan // Chinese text is intentional for Weibo
		prof.Name = strings.TrimSpace(prof.Name)
	}

	// Extract bio/description
	prof.Bio = htmlutil.Description(html)

	// Try to extract follower count (关注/粉丝)
	followerPattern := regexp.MustCompile(`(\d+)\s*(?:粉丝|Followers)`) //nolint:gosmopolitan // Chinese text is intentional for Weibo
	if matches := followerPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["followers"] = matches[1]
	}

	followingPattern := regexp.MustCompile(`(\d+)\s*(?:关注|Following)`) //nolint:gosmopolitan // Chinese text is intentional for Weibo
	if matches := followingPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["following"] = matches[1]
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(html)

	// Filter out Weibo's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "weibo.com") && !strings.Contains(link, "weibo.cn") {
			filtered = append(filtered, link)
		}
	}
	prof.SocialLinks = filtered

	if prof.Name == "" {
		prof.Name = prof.Username
	}

	return prof, nil
}

func extractUsername(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")

	// Extract weibo.com/u/12345 or weibo.com/username patterns
	re := regexp.MustCompile(`weibo\.(?:com|cn)/(?:u/)?([^/?#]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
