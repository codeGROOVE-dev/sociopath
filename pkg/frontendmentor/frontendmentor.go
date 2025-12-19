// Package frontendmentor fetches Frontend Mentor user profile data.
package frontendmentor

import (
	"context"
	"encoding/json"
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

const platform = "frontendmentor"

// platformInfo implements profile.Platform for Frontend Mentor.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeCode }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)frontendmentor\.io/profile/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Frontend Mentor profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "frontendmentor.io/profile/") {
		return false
	}
	// Exclude non-profile paths
	excludePaths := []string{"/challenges/", "/solutions/", "/faq", "/learning-paths/", "/pro", "/about", "/contact"}
	for _, p := range excludePaths {
		if strings.Contains(lower, p) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Frontend Mentor profiles are public.
func AuthRequired() bool { return false }

// Client handles Frontend Mentor requests.
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

// New creates a Frontend Mentor client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

// nextData represents the __NEXT_DATA__ JSON structure.
type nextData struct {
	Props struct {
		PageProps map[string]any `json:"pageProps"`
	} `json:"props"`
}

// Pattern to extract __NEXT_DATA__ JSON.
var nextDataPattern = regexp.MustCompile(`__NEXT_DATA__"[^>]*>(\{.+?\})</script>`)

// Fetch retrieves a Frontend Mentor profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching frontendmentor profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://www.frontendmentor.io/profile/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return c.parseProfile(ctx, string(body), profileURL, username)
}

func (c *Client) parseProfile(ctx context.Context, html, profileURL, username string) (*profile.Profile, error) {
	p := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Try to extract __NEXT_DATA__ JSON
	match := nextDataPattern.FindStringSubmatch(html)
	if len(match) >= 2 {
		var nd nextData
		if err := json.Unmarshal([]byte(match[1]), &nd); err == nil {
			if profileData, ok := nd.Props.PageProps["profile"].(map[string]any); ok {
				c.extractFromJSON(profileData, p)
			} else if user, ok := nd.Props.PageProps["user"].(map[string]any); ok {
				c.extractFromJSON(user, p)
			}
		}
	}

	// Fallback to HTML parsing for any missing fields
	c.extractFromHTML(html, p)

	// Extract social links
	p.SocialLinks = htmlutil.RelMeLinks(html)
	if len(p.SocialLinks) == 0 {
		// Fallback to generic social link extraction
		p.SocialLinks = htmlutil.SocialLinks(html)
	}

	return p, nil
}

func (c *Client) extractFromJSON(data map[string]any, p *profile.Profile) {
	if username, ok := data["username"].(string); ok && p.Username == "" {
		p.Username = username
	}
	if name, ok := data["name"].(string); ok {
		p.DisplayName = name
	}
	if avatar, ok := data["avatar"].(string); ok {
		p.AvatarURL = avatar
	} else if profileImage, ok := data["profileImage"].(string); ok {
		p.AvatarURL = profileImage
	}
	if bio, ok := data["bio"].(string); ok {
		p.Bio = strings.TrimSpace(bio)
	}
	if location, ok := data["location"].(string); ok {
		p.Location = strings.TrimSpace(location)
	}
	if website, ok := data["website"].(string); ok {
		p.Website = strings.TrimSpace(website)
	}
	if github, ok := data["github"].(string); ok && github != "" {
		github = normalizeGitHubURL(github)
		p.Fields["github"] = github
		p.SocialLinks = append(p.SocialLinks, github)
	}
	if twitter, ok := data["twitter"].(string); ok && twitter != "" {
		twitter = normalizeTwitterURL(twitter)
		p.Fields["twitter"] = twitter
		p.SocialLinks = append(p.SocialLinks, twitter)
	}
	if linkedin, ok := data["linkedin"].(string); ok && linkedin != "" {
		linkedin = normalizeLinkedInURL(linkedin)
		p.Fields["linkedin"] = linkedin
		p.SocialLinks = append(p.SocialLinks, linkedin)
	}

	// Extract stats
	if points, ok := data["points"].(float64); ok {
		p.Fields["points"] = fmt.Sprintf("%.0f", points)
	}
	if rank, ok := data["rank"].(float64); ok {
		p.Fields["rank"] = fmt.Sprintf("%.0f", rank)
	} else if rank, ok := data["ranking"].(float64); ok {
		p.Fields["rank"] = fmt.Sprintf("%.0f", rank)
	}
	if completed, ok := data["challengesCompleted"].(float64); ok {
		p.Fields["challenges_completed"] = fmt.Sprintf("%.0f", completed)
	} else if completed, ok := data["completed"].(float64); ok {
		p.Fields["challenges_completed"] = fmt.Sprintf("%.0f", completed)
	}
}

func (c *Client) extractFromHTML(html string, p *profile.Profile) {
	// Extract display name from title or meta tags
	if p.DisplayName == "" {
		if title := htmlutil.Title(html); title != "" {
			// Title format might be "Username | Frontend Mentor" or "Name's Profile"
			title = strings.Split(title, " | Frontend Mentor")[0]
			title = strings.TrimSuffix(title, "'s profile")
			title = strings.TrimSuffix(title, "'s Profile")
			title = strings.TrimSpace(title)
			if title != "" && title != p.Username {
				p.DisplayName = title
			}
		}
	}

	// Extract avatar from og:image or similar
	if p.AvatarURL == "" {
		p.AvatarURL = htmlutil.OGImage(html)
	}

	// Extract description as bio if not found
	if p.Bio == "" {
		if desc := htmlutil.Description(html); desc != "" {
			p.Bio = desc
		}
	}
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func normalizeGitHubURL(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	// If it's just a username, construct full URL
	if !strings.Contains(input, "://") {
		input = strings.TrimPrefix(input, "@")
		return "https://github.com/" + input
	}
	// Ensure https://
	if strings.HasPrefix(input, "http://") {
		input = strings.Replace(input, "http://", "https://", 1)
	}
	return input
}

func normalizeTwitterURL(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	// If it's just a username, construct full URL
	if !strings.Contains(input, "://") {
		input = strings.TrimPrefix(input, "@")
		return "https://twitter.com/" + input
	}
	// Ensure https://
	if strings.HasPrefix(input, "http://") {
		input = strings.Replace(input, "http://", "https://", 1)
	}
	// Normalize x.com to twitter.com
	input = strings.Replace(input, "x.com/", "twitter.com/", 1)
	return input
}

func normalizeLinkedInURL(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	// If it's not a full URL, construct it
	if !strings.Contains(input, "://") {
		return "https://www.linkedin.com/in/" + input
	}
	// Ensure https://
	if strings.HasPrefix(input, "http://") {
		input = strings.Replace(input, "http://", "https://", 1)
	}
	return input
}
