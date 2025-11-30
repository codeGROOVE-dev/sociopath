// Package twitter fetches Twitter/X user profile data using authenticated session cookies.
package twitter

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
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/auth"
	"github.com/codeGROOVE-dev/sociopath/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/profile"
)

const platform = "twitter"

// Match returns true if the URL is a Twitter/X profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "twitter.com/") || strings.Contains(lower, "x.com/")
}

// IsValidUsername validates a Twitter username against platform requirements.
// Twitter usernames must be 1-15 characters and contain only alphanumeric or underscore.
func IsValidUsername(username string) bool {
	if len(username) < 1 || len(username) > 15 {
		return false
	}
	for _, r := range username {
		isLower := r >= 'a' && r <= 'z'
		isUpper := r >= 'A' && r <= 'Z'
		isDigit := r >= '0' && r <= '9'
		isUnderscore := r == '_'
		if !isLower && !isUpper && !isDigit && !isUnderscore {
			return false
		}
	}
	return true
}

// IsValidProfileURL validates that a Twitter/X URL points to an actual user profile,
// filtering out system pages, language codes, and invalid usernames.
func IsValidProfileURL(urlStr string) bool {
	lower := strings.ToLower(urlStr)

	if !Match(urlStr) {
		return false
	}

	// Extract the path after the domain
	for _, domain := range []string{"twitter.com/", "x.com/"} {
		idx := strings.Index(lower, domain)
		if idx < 0 {
			continue
		}

		path := lower[idx+len(domain):]
		path = strings.Split(path, "/")[0]
		path = strings.Split(path, "?")[0]

		// Skip system pages
		systemPages := map[string]bool{
			"tos": true, "privacy": true, "messages": true, "settings": true,
			"search": true, "explore": true, "notifications": true, "home": true,
			"login": true, "logout": true, "signup": true, "i": true,
			"compose": true, "intent": true, "share": true, "hashtag": true,
			"about": true, "help": true, "rules": true, "ads": true,
			"content": true,
		}
		if systemPages[path] {
			return false
		}

		// Skip 2-letter language codes
		if len(path) == 2 {
			return false
		}

		// Validate username
		return IsValidUsername(path)
	}

	return true
}

// AuthRequired returns true because Twitter requires authentication.
func AuthRequired() bool { return true }

// Client handles Twitter/X requests with authenticated cookies.
type Client struct {
	httpClient *http.Client
	logger     *slog.Logger
	debug      bool
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cookies        map[string]string
	logger         *slog.Logger
	browserCookies bool
}

// WithCookies sets explicit cookie values.
func WithCookies(cookies map[string]string) Option {
	return func(c *config) { c.cookies = cookies }
}

// WithBrowserCookies enables reading cookies from browser stores.
func WithBrowserCookies() Option {
	return func(c *config) { c.browserCookies = true }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates a Twitter client.
// Cookie sources: WithCookies > environment variables > browser.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

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

	jar, err := auth.NewCookieJar("x.com", cookies)
	if err != nil {
		return nil, fmt.Errorf("cookie jar creation failed: %w", err)
	}

	cfg.logger.InfoContext(ctx, "twitter client created", "cookie_count", len(cookies))

	return &Client{
		httpClient: &http.Client{Jar: jar, Timeout: 3 * time.Second},
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a Twitter profile using GraphQL API.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	profileURL := "https://x.com/" + username
	c.logger.InfoContext(ctx, "fetching twitter profile via graphql", "url", profileURL, "username", username)

	// Try GraphQL API first
	p, err := c.fetchViaGraphQL(ctx, username, profileURL)
	if err == nil {
		return p, nil
	}

	c.logger.Debug("graphql fetch failed, trying html fallback", "error", err)

	// Fallback to HTML parsing
	return c.fetchViaHTML(ctx, username, profileURL)
}

// fetchViaGraphQL uses Twitter's GraphQL API to fetch profile data.
func (c *Client) fetchViaGraphQL(ctx context.Context, username, profileURL string) (*profile.Profile, error) {
	// Build GraphQL query
	variables := map[string]any{
		"screen_name":                username,
		"withSafetyModeUserFields":   true,
		"withSuperFollowsUserFields": true,
	}
	varsJSON, err := json.Marshal(variables)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal variables: %w", err)
	}

	features := getGraphQLFeatures()
	featJSON, err := json.Marshal(features)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal features: %w", err)
	}

	queryID := "-oaLodhGbbnzJBACb1kk2Q" // UserByScreenName operation ID
	apiURL := fmt.Sprintf("https://x.com/i/api/graphql/%s/UserByScreenName?variables=%s&features=%s",
		queryID,
		url.QueryEscape(string(varsJSON)),
		url.QueryEscape(string(featJSON)))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}

	setGraphQLHeaders(req, c.httpClient, profileURL)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // error ignored intentionally

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		c.logger.Debug("graphql api error", "status", resp.StatusCode, "body", string(body))
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	c.logger.Debug("graphql response received", "size", len(body))

	return parseGraphQLResponse(body, profileURL, username)
}

// fetchViaHTML falls back to HTML parsing (legacy method).
func (c *Client) fetchViaHTML(ctx context.Context, username, profileURL string) (*profile.Profile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}

	setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // error ignored intentionally

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response failed: %w", err)
	}

	return c.parseProfile(body, profileURL, username)
}

// EnableDebug enables debug logging.
func (c *Client) EnableDebug() { c.debug = true }

func setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
}

func (c *Client) parseProfile(body []byte, profileURL, targetUsername string) (*profile.Profile, error) {
	content := string(body)

	initialState := extractInitialState(content)
	if initialState == "" {
		c.logger.Debug("failed to find __INITIAL_STATE__ in page", "url", profileURL)
		return nil, errors.New("could not find __INITIAL_STATE__ in page")
	}

	c.logger.Debug("found __INITIAL_STATE__", "length", len(initialState))

	var state map[string]any
	if err := json.Unmarshal([]byte(initialState), &state); err != nil {
		return nil, fmt.Errorf("failed to parse __INITIAL_STATE__: %w", err)
	}

	// Try to extract from timeline first (newer Twitter format)
	p, err := c.extractFromTimeline(state, targetUsername)
	if err == nil {
		p.Platform = platform
		p.URL = profileURL
		p.Authenticated = true
		p.SocialLinks = htmlutil.SocialLinks(content)
		return p, nil
	}

	c.logger.Debug("timeline extraction failed, trying legacy format", "error", err)

	// Fallback to legacy user entities format
	p, err = c.extractUserFromState(state, targetUsername)
	if err != nil {
		c.logger.Debug("legacy extraction also failed", "error", err)
		return nil, errors.New("profile data not embedded in page (Twitter may require API calls for this profile)")
	}

	p.Platform = platform
	p.URL = profileURL
	p.Authenticated = true
	p.SocialLinks = htmlutil.SocialLinks(content)

	return p, nil
}

func extractInitialState(content string) string {
	re := regexp.MustCompile(`window\.__INITIAL_STATE__\s*=\s*(\{.+?\});?\s*(?:</script>|window\.)`)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		return matches[1]
	}

	re2 := regexp.MustCompile(`(?s)window\.__INITIAL_STATE__\s*=\s*(\{.*?\});\s*</script>`)
	if matches := re2.FindStringSubmatch(content); len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func (c *Client) extractFromTimeline(state map[string]any, targetUsername string) (*profile.Profile, error) {
	entities, ok := state["entities"].(map[string]any)
	if !ok {
		return nil, errors.New("no entities in state")
	}

	users, ok := entities["users"].(map[string]any)
	if !ok {
		return nil, errors.New("no users in entities")
	}

	usersEntities, ok := users["entities"].(map[string]any)
	if !ok {
		return nil, errors.New("no user entities")
	}

	c.logger.Debug("searching timeline for user", "target", targetUsername, "user_count", len(usersEntities))

	// Search all user entities for matching screen_name
	for userID, userData := range usersEntities {
		user, ok := userData.(map[string]any)
		if !ok {
			continue
		}

		screenName, ok := user["screen_name"].(string)
		if !ok {
			continue
		}

		c.logger.Debug("found user in timeline", "user_id", userID, "screen_name", screenName)

		if strings.EqualFold(screenName, targetUsername) {
			c.logger.Debug("matched target user", "screen_name", screenName)
			return c.buildProfileFromUser(user, screenName), nil
		}
	}

	return nil, fmt.Errorf("user %q not found in timeline entities", targetUsername)
}

func (c *Client) extractUserFromState(state map[string]any, targetUsername string) (*profile.Profile, error) {
	c.logger.Debug("parsing state", "top_level_keys", getKeys(state))

	entities, ok := state["entities"].(map[string]any)
	if !ok {
		c.logger.Debug("no entities found in state")
		return nil, errors.New("no entities found in state")
	}

	c.logger.Debug("found entities", "keys", getKeys(entities))

	users, ok := entities["users"].(map[string]any)
	if !ok {
		c.logger.Debug("no users found in entities")
		return nil, errors.New("no users found in entities")
	}

	c.logger.Debug("found users", "keys", getKeys(users))

	usersEntities, ok := users["entities"].(map[string]any)
	if !ok {
		c.logger.Debug("no user entities found")
		return nil, errors.New("no user entities found")
	}

	c.logger.Debug("found user entities", "count", len(usersEntities))

	for userID, userData := range usersEntities {
		user, ok := userData.(map[string]any)
		if !ok {
			c.logger.Debug("skipping non-map user data", "user_id", userID)
			continue
		}

		screenName, ok := user["screen_name"].(string)
		c.logger.Debug("checking user", "user_id", userID, "screen_name", screenName, "target", targetUsername)

		if !ok || !strings.EqualFold(screenName, targetUsername) {
			continue
		}

		return c.buildProfileFromUser(user, screenName), nil
	}

	return nil, fmt.Errorf("user %q not found in page data", targetUsername)
}

func (*Client) buildProfileFromUser(user map[string]any, screenName string) *profile.Profile {
	p := &profile.Profile{
		Username: screenName,
		Fields:   make(map[string]string),
	}

	if name, ok := user["name"].(string); ok {
		p.Name = name
	}
	if desc, ok := user["description"].(string); ok {
		p.Bio = desc
	}
	if loc, ok := user["location"].(string); ok {
		p.Location = loc
	}

	p.Website = extractWebsiteFromUser(user)

	return p
}

func extractWebsiteFromUser(user map[string]any) string {
	entities, ok := user["entities"].(map[string]any)
	if !ok {
		return ""
	}

	urlData, ok := entities["url"].(map[string]any)
	if !ok {
		return ""
	}

	urls, ok := urlData["urls"].([]any)
	if !ok || len(urls) == 0 {
		return ""
	}

	firstURL, ok := urls[0].(map[string]any)
	if !ok {
		return ""
	}

	if expandedURL, ok := firstURL["expanded_url"].(string); ok {
		return expandedURL
	}
	if displayURL, ok := firstURL["display_url"].(string); ok {
		return displayURL
	}

	return ""
}

func extractUsername(s string) string {
	if strings.Contains(s, "/") {
		re := regexp.MustCompile(`(?:x\.com|twitter\.com)/([^/?]+)`)
		if m := re.FindStringSubmatch(s); len(m) > 1 {
			return m[1]
		}
	}
	return strings.TrimPrefix(s, "@")
}

func getKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

const twitterBearerToken = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"

// setGraphQLHeaders sets the required headers for GraphQL API requests.
func setGraphQLHeaders(req *http.Request, client *http.Client, referer string) {
	req.Header.Set("Authorization", "Bearer "+twitterBearerToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("X-Twitter-Auth-Type", "OAuth2Session")
	req.Header.Set("X-Twitter-Active-User", "yes")
	req.Header.Set("Referer", referer)

	// Extract ct0 cookie and set as X-Csrf-Token
	if parsedURL, err := url.Parse("https://x.com"); err == nil {
		cookies := client.Jar.Cookies(parsedURL)
		for _, cookie := range cookies {
			if cookie.Name == "ct0" {
				req.Header.Set("X-Csrf-Token", cookie.Value)
				break
			}
		}
	}
}

// getGraphQLFeatures returns the feature flags for GraphQL requests.
func getGraphQLFeatures() map[string]bool {
	return map[string]bool{
		"articles_preview_enabled":                                                true,
		"blue_business_profile_image_shape_enabled":                               false,
		"c9s_tweet_anatomy_moderator_badge_enabled":                               true,
		"communities_web_enable_tweet_community_results_fetch":                    true,
		"creator_subscriptions_quote_tweet_preview_enabled":                       true,
		"creator_subscriptions_tweet_preview_api_enabled":                         true,
		"freedom_of_speech_not_reach_fetch_enabled":                               true,
		"graphql_is_translatable_rweb_tweet_is_translatable_enabled":              true,
		"hidden_profile_subscriptions_enabled":                                    false,
		"highlights_tweets_tab_ui_enabled":                                        true,
		"longform_notetweets_consumption_enabled":                                 true,
		"longform_notetweets_inline_media_enabled":                                true,
		"longform_notetweets_rich_text_read_enabled":                              true,
		"profile_label_improvements_pcf_label_in_post_enabled":                    true,
		"responsive_web_enhance_cards_enabled":                                    true,
		"responsive_web_graphql_exclude_directive_enabled":                        true,
		"responsive_web_graphql_skip_user_profile_image_extensions_enabled":       false,
		"responsive_web_graphql_timeline_navigation_enabled":                      true,
		"responsive_web_profile_redirect_enabled":                                 true,
		"responsive_web_twitter_article_notes_tab_enabled":                        true,
		"responsive_web_twitter_article_tweet_consumption_enabled":                true,
		"rweb_tipjar_consumption_enabled":                                         true,
		"rweb_video_screen_enabled":                                               true,
		"standardized_nudges_misinfo":                                             true,
		"subscriptions_feature_can_gift_premium":                                  true,
		"subscriptions_verification_info_is_identity_verified_enabled":            true,
		"subscriptions_verification_info_verified_since_enabled":                  true,
		"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": true,
		"verified_phone_label_enabled":                                            false,
		"view_counts_everywhere_api_enabled":                                      true,
	}
}

// parseGraphQLResponse parses the GraphQL API response.
func parseGraphQLResponse(body []byte, profileURL, _ string) (*profile.Profile, error) {
	var resp struct {
		Data struct {
			User struct {
				Result struct {
					RestID string `json:"rest_id"`
					Core   struct {
						Name       string `json:"name"`
						ScreenName string `json:"screen_name"`
					} `json:"core"`
					Location struct {
						Location string `json:"location"`
					} `json:"location"`
					Legacy struct {
						Description string `json:"description"`
						Entities    struct {
							URL struct {
								URLs []struct {
									ExpandedURL string `json:"expanded_url"`
									DisplayURL  string `json:"display_url"`
								} `json:"urls"`
							} `json:"url"`
						} `json:"entities"`
					} `json:"legacy"`
				} `json:"result"`
			} `json:"user"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse graphql response: %w", err)
	}

	if resp.Data.User.Result.RestID == "" {
		return nil, errors.New("user not found in graphql response")
	}

	result := resp.Data.User.Result

	p := &profile.Profile{
		Platform:      platform,
		URL:           profileURL,
		Authenticated: true,
		Username:      result.Core.ScreenName,
		Name:          result.Core.Name,
		Bio:           result.Legacy.Description,
		Location:      result.Location.Location,
		Fields:        make(map[string]string),
	}

	// Extract website
	if len(result.Legacy.Entities.URL.URLs) > 0 {
		if result.Legacy.Entities.URL.URLs[0].ExpandedURL != "" {
			p.Website = result.Legacy.Entities.URL.URLs[0].ExpandedURL
		} else if result.Legacy.Entities.URL.URLs[0].DisplayURL != "" {
			p.Website = result.Legacy.Entities.URL.URLs[0].DisplayURL
		}
	}

	return p, nil
}
