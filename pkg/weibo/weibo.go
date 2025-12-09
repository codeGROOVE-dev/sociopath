// Package weibo fetches Weibo user profile data using authenticated session cookies.
package weibo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/auth"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "weibo"

// Match returns true if the URL is a Weibo profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	// Must match actual weibo domains, not substrings like "notweibo.com"
	return strings.Contains(lower, "://weibo.com/") ||
		strings.Contains(lower, "://www.weibo.com/") ||
		strings.Contains(lower, "://weibo.cn/") ||
		strings.Contains(lower, "://www.weibo.cn/")
}

// AuthRequired returns true because Weibo requires authentication.
func AuthRequired() bool { return true }

// Client handles Weibo requests with authenticated cookies.
type Client struct {
	httpClient *http.Client
	cache      *httpcache.Cache
	logger     *slog.Logger
	sub        string
	subp       string
	xsrfToken  string
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cookies        map[string]string
	cache          *httpcache.Cache
	logger         *slog.Logger
	browserCookies bool
}

// WithCookies sets explicit cookie values.
func WithCookies(cookies map[string]string) Option {
	return func(c *config) { c.cookies = cookies }
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache *httpcache.Cache) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithBrowserCookies enables reading cookies from browser stores.
func WithBrowserCookies() Option {
	return func(c *config) { c.browserCookies = true }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates a Weibo client.
// Cookie sources are checked in order: WithCookies > environment > browser.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	// Build cookie sources chain
	var sources []auth.Source
	if len(cfg.cookies) > 0 {
		sources = append(sources, auth.NewStaticSource(cfg.cookies))
	}
	sources = append(sources, auth.EnvSource{})
	if cfg.browserCookies {
		sources = append(sources, auth.NewBrowserSource(cfg.logger))
	}

	cookies, err := auth.ChainSources(ctx, platform, sources...)
	if err != nil {
		return nil, fmt.Errorf("cookie retrieval failed: %w", err)
	}
	if len(cookies) == 0 {
		envVars := auth.EnvVarsForPlatform(platform)
		return nil, fmt.Errorf("%w: set %v or use WithCookies/WithBrowserCookies",
			profile.ErrNoCookies, envVars)
	}

	sub := cookies["SUB"]
	subp := cookies["SUBP"]
	if sub == "" || subp == "" {
		return nil, fmt.Errorf("%w: missing SUB or SUBP cookies", profile.ErrNoCookies)
	}

	cfg.logger.InfoContext(ctx, "weibo client created", "cookie_count", len(cookies))

	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
		sub:    sub,
		subp:   subp,
	}, nil
}

// Fetch retrieves a Weibo profile from the given URL.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := ExtractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching weibo profile", "url", urlStr, "username", username)

	// Get XSRF token first
	if err := c.fetchXSRFToken(ctx, username); err != nil {
		return nil, fmt.Errorf("fetching XSRF token: %w", err)
	}

	// Resolve username to UID if needed
	uid := username
	if !isNumeric(username) {
		resolvedUID, err := c.resolveUsername(ctx, username)
		if err != nil {
			return nil, fmt.Errorf("resolving username: %w", err)
		}
		uid = resolvedUID
	}

	// Fetch profile detail
	weiboProfile, err := c.fetchProfileDetail(ctx, uid)
	if err != nil {
		return nil, err
	}

	// Enrich with side detail (non-fatal if it fails)
	_ = c.enrichWithSideDetail(ctx, uid, weiboProfile) //nolint:errcheck // Non-fatal enrichment

	// Convert to common profile format
	return c.toProfile(weiboProfile, urlStr), nil
}

// weiboProfile holds the raw Weibo profile data.
type weiboProfile struct {
	UID            string
	ScreenName     string
	Description    string
	VerifiedReason string
	Location       string
	Hometown       string
	Company        string
	School         string
	Gender         string
	CreatedAt      string
	FollowersCount int
	FriendsCount   int
	StatusesCount  int
	Verified       bool
}

func (*Client) toProfile(wp *weiboProfile, urlStr string) *profile.Profile {
	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: true,
		Username:      wp.ScreenName,
		Name:          wp.ScreenName,
		Bio:           wp.Description,
		Location:      wp.Location,
		Fields:        make(map[string]string),
	}

	if wp.VerifiedReason != "" {
		p.Fields["verified_reason"] = wp.VerifiedReason
	}
	if wp.Company != "" {
		p.Fields["employer"] = wp.Company
	}
	if wp.School != "" {
		p.Fields["school"] = wp.School
	}
	if wp.Hometown != "" {
		p.Fields["hometown"] = wp.Hometown
	}
	if wp.Gender != "" {
		p.Fields["gender"] = wp.Gender
	}
	if wp.Verified {
		p.Fields["verified"] = "true"
	}
	if wp.FollowersCount > 0 {
		p.Fields["followers"] = strconv.Itoa(wp.FollowersCount)
	}

	return p
}

func (c *Client) fetchXSRFToken(ctx context.Context, username string) error {
	pageURL := fmt.Sprintf("https://weibo.com/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, pageURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	setCommonHeaders(req)
	req.Header.Set("Cookie", fmt.Sprintf("SUB=%s; SUBP=%s", c.sub, c.subp))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching page: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // Best-effort close

	// Extract XSRF-TOKEN from Set-Cookie header
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "XSRF-TOKEN" {
			c.xsrfToken = cookie.Value
			c.logger.DebugContext(ctx, "got XSRF token", "token_length", len(c.xsrfToken))
			return nil
		}
	}

	return errors.New("XSRF-TOKEN not found in response")
}

func (c *Client) resolveUsername(ctx context.Context, username string) (string, error) {
	apiURL := fmt.Sprintf("https://weibo.com/ajax/profile/info?custom=%s", url.QueryEscape(username))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return "", err
	}

	setCommonHeaders(req)
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck // Best-effort close

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result struct {
		Data struct {
			User struct {
				IDStr string `json:"idstr"`
			} `json:"user"`
		} `json:"data"`
		OK int `json:"ok"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}

	if result.OK != 1 || result.Data.User.IDStr == "" {
		return "", fmt.Errorf("%w: %s", profile.ErrProfileNotFound, username)
	}

	return result.Data.User.IDStr, nil
}

func (c *Client) fetchProfileDetail(ctx context.Context, uid string) (*weiboProfile, error) {
	apiURL := fmt.Sprintf("https://weibo.com/ajax/profile/detail?uid=%s", uid)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}

	setCommonHeaders(req)
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // Best-effort close

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data struct {
			Description string `json:"description"`
			DescText    string `json:"desc_text"`
			Hometown    string `json:"hometown"`
			Birthday    string `json:"birthday"`
			CreatedAt   string `json:"created_at"`
			IPLocation  string `json:"ip_location"`
			Company     string `json:"company"`
			Gender      string `json:"gender"`
			Career      struct {
				Company string `json:"company"`
			} `json:"career"`
			Education struct {
				School string `json:"school"`
			} `json:"education"`
		} `json:"data"`
		OK int `json:"ok"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if result.OK != 1 {
		return nil, fmt.Errorf("%w: uid %s", profile.ErrProfileNotFound, uid)
	}

	wp := &weiboProfile{
		UID:            uid,
		Description:    result.Data.Description,
		VerifiedReason: result.Data.DescText,
		Gender:         result.Data.Gender,
		Hometown:       cleanHometown(result.Data.Hometown),
		CreatedAt:      result.Data.CreatedAt,
	}

	// Company can be in either field
	if result.Data.Company != "" {
		wp.Company = result.Data.Company
	} else if result.Data.Career.Company != "" {
		wp.Company = result.Data.Career.Company
	}

	if result.Data.Education.School != "" {
		wp.School = result.Data.Education.School
	}

	return wp, nil
}

func (c *Client) enrichWithSideDetail(ctx context.Context, uid string, wp *weiboProfile) error {
	apiURL := fmt.Sprintf("https://weibo.com/ajax/profile/sidedetail?uid=%s", uid)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return err
	}

	setCommonHeaders(req)
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // Best-effort close

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var result struct {
		Data struct {
			Service []struct {
				Button struct {
					Params struct {
						User struct {
							ScreenName     string `json:"screen_name"`
							Location       string `json:"location"`
							Description    string `json:"description"`
							VerifiedReason string `json:"verified_reason"`
							FollowersCount int    `json:"followers_count"`
							FriendsCount   int    `json:"friends_count"`
							StatusesCount  int    `json:"statuses_count"`
							Verified       bool   `json:"verified"`
						} `json:"user"`
					} `json:"params"`
				} `json:"button"`
			} `json:"service"`
		} `json:"data"`
		OK int `json:"ok"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}

	if result.OK != 1 || len(result.Data.Service) == 0 {
		return errors.New("no service data")
	}

	user := result.Data.Service[0].Button.Params.User
	wp.ScreenName = user.ScreenName
	wp.Location = user.Location
	wp.FollowersCount = user.FollowersCount
	wp.FriendsCount = user.FriendsCount
	wp.StatusesCount = user.StatusesCount
	wp.Verified = user.Verified

	if wp.VerifiedReason == "" && user.VerifiedReason != "" {
		wp.VerifiedReason = user.VerifiedReason
	}

	if wp.Description == "" && user.Description != "" {
		wp.Description = user.Description
	}

	return nil
}

func setCommonHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Referer", "https://weibo.com/")
}

func (c *Client) setAuthHeaders(req *http.Request) {
	cookie := fmt.Sprintf("SUB=%s; SUBP=%s", c.sub, c.subp)
	if c.xsrfToken != "" {
		cookie += fmt.Sprintf("; XSRF-TOKEN=%s", c.xsrfToken)
		req.Header["X-Xsrf-Token"] = []string{c.xsrfToken}
	}
	req.Header.Set("Cookie", cookie)
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func cleanHometown(s string) string {
	prefixes := []string{
		"\u5bb6\u4e61\uff1a", // 家乡：(full-width colon)
		"\u5bb6\u4e61:",      // 家乡: (half-width colon)
	}
	for _, prefix := range prefixes {
		s = strings.TrimPrefix(s, prefix)
	}
	return strings.TrimSpace(s)
}

// ExtractUsername extracts the username from a Weibo URL.
func ExtractUsername(weiboURL string) string {
	re := regexp.MustCompile(`https?://(?:www\.)?weibo\.(?:com|cn)/(?:u/)?([^/?#]+)`)
	matches := re.FindStringSubmatch(weiboURL)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
