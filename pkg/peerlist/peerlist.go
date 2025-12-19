// Package peerlist fetches Peerlist user profile data.
package peerlist

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

const platform = "peerlist"

// platformInfo implements profile.Platform for Peerlist.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)peerlist\.io/([a-zA-Z0-9_.-]+)`)

// Match returns true if the URL is a Peerlist profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "peerlist.io/") {
		return false
	}
	// Exclude non-profile paths
	excludePaths := []string{"/blog/", "/launchpad/", "/scroll/", "/company/", "/signup", "/login", "/about", "/privacy", "/terms", "/jobs"}
	for _, p := range excludePaths {
		if strings.Contains(lower, p) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Peerlist profiles are public.
func AuthRequired() bool { return false }

// Client handles Peerlist requests.
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

// New creates a Peerlist client.
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
		PageProps struct {
			UserData *userData `json:"userData"`
			Profile  *userData `json:"profile"`
		} `json:"pageProps"`
	} `json:"props"`
}

// userData represents a Peerlist user.
type userData struct {
	ID          string            `json:"id"`
	Username    string            `json:"username"`
	Name        string            `json:"name"`
	FirstName   string            `json:"firstName"`
	LastName    string            `json:"lastName"`
	Avatar      string            `json:"avatar"`
	ProfilePic  string            `json:"profilePic"`
	Headline    string            `json:"headline"`
	Bio         string            `json:"bio"`
	Location    string            `json:"location"`
	Website     string            `json:"website"`
	GitHub      string            `json:"github"`
	Twitter     string            `json:"twitter"`
	LinkedIn    string            `json:"linkedin"`
	Resume      string            `json:"resume"`
	Skills      []string          `json:"skills"`
	Following   int               `json:"following"`
	Followers   int               `json:"followers"`
	Verified    bool              `json:"verified"`
	CreatedAt   string            `json:"createdAt"`
	SocialLinks []socialLink      `json:"socialLinks"`
	Links       map[string]string `json:"links"`
}

// socialLink represents a social media link.
type socialLink struct {
	Type  string `json:"type"`
	URL   string `json:"url"`
	Label string `json:"label"`
}

// Pattern to extract __NEXT_DATA__ JSON.
var nextDataPattern = regexp.MustCompile(`__NEXT_DATA__"[^>]*>(\{.+?\})</script>`)

// Fetch retrieves a Peerlist profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching peerlist profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://peerlist.io/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, nil)
	if err != nil {
		return nil, err
	}
	// Use a realistic User-Agent to avoid 403 errors
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return c.parseProfile(ctx, string(body), profileURL, username)
}

func (c *Client) parseProfile(_ context.Context, html, profileURL, username string) (*profile.Profile, error) {
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
			// Try both userData and profile fields
			if nd.Props.PageProps.UserData != nil {
				c.extractFromJSON(nd.Props.PageProps.UserData, p)
			} else if nd.Props.PageProps.Profile != nil {
				c.extractFromJSON(nd.Props.PageProps.Profile, p)
			}
		}
	}

	// Fallback to HTML parsing for any missing fields
	c.extractFromHTML(html, p)

	// Extract social links
	if len(p.SocialLinks) == 0 {
		p.SocialLinks = htmlutil.RelMeLinks(html)
		if len(p.SocialLinks) == 0 {
			p.SocialLinks = htmlutil.SocialLinks(html)
		}
	}

	return p, nil
}

func (c *Client) extractFromJSON(user *userData, p *profile.Profile) {
	if user.Username != "" {
		p.Username = user.Username
	}
	if user.Name != "" {
		p.DisplayName = user.Name
	} else if user.FirstName != "" || user.LastName != "" {
		// Construct name from firstName + lastName
		p.DisplayName = strings.TrimSpace(user.FirstName + " " + user.LastName)
	}
	if user.Avatar != "" {
		p.AvatarURL = user.Avatar
	} else if user.ProfilePic != "" {
		p.AvatarURL = user.ProfilePic
	}
	if user.Headline != "" {
		p.Bio = strings.TrimSpace(user.Headline)
	} else if user.Bio != "" {
		p.Bio = strings.TrimSpace(user.Bio)
	}
	if user.Location != "" {
		p.Location = strings.TrimSpace(user.Location)
	}
	if user.Website != "" {
		p.Website = strings.TrimSpace(user.Website)
	}
	if user.CreatedAt != "" {
		p.CreatedAt = user.CreatedAt
	}

	// Extract social links
	if user.GitHub != "" {
		github := normalizeGitHubURL(user.GitHub)
		p.Fields["github"] = github
		p.SocialLinks = append(p.SocialLinks, github)
	}
	if user.Twitter != "" {
		twitter := normalizeTwitterURL(user.Twitter)
		p.Fields["twitter"] = twitter
		p.SocialLinks = append(p.SocialLinks, twitter)
	}
	if user.LinkedIn != "" {
		linkedin := normalizeLinkedInURL(user.LinkedIn)
		p.Fields["linkedin"] = linkedin
		p.SocialLinks = append(p.SocialLinks, linkedin)
	}

	// Extract additional social links
	for _, social := range user.SocialLinks {
		if social.URL != "" && !contains(p.SocialLinks, social.URL) {
			p.SocialLinks = append(p.SocialLinks, social.URL)
		}
	}

	// Extract links map
	for key, url := range user.Links {
		if url != "" && !contains(p.SocialLinks, url) {
			p.Fields[key] = url
			p.SocialLinks = append(p.SocialLinks, url)
		}
	}

	// Extract skills
	if len(user.Skills) > 0 {
		// Store skills as comma-separated string
		p.Fields["skills"] = strings.Join(user.Skills, ", ")
	}

	// Extract stats
	if user.Followers > 0 {
		p.Fields["followers"] = fmt.Sprintf("%d", user.Followers)
	}
	if user.Following > 0 {
		p.Fields["following"] = fmt.Sprintf("%d", user.Following)
	}
	if user.Verified {
		p.Fields["verified"] = "true"
	}
}

func (c *Client) extractFromHTML(html string, p *profile.Profile) {
	// Extract display name from title or meta tags
	if p.DisplayName == "" {
		if title := htmlutil.Title(html); title != "" {
			title = strings.Split(title, " - Peerlist")[0]
			title = strings.Split(title, " | Peerlist")[0]
			title = strings.TrimSpace(title)
			if title != "" && title != p.Username {
				p.DisplayName = title
			}
		}
	}

	// Extract avatar from og:image
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
	if !strings.Contains(input, "://") {
		input = strings.TrimPrefix(input, "@")
		return "https://github.com/" + input
	}
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
	if !strings.Contains(input, "://") {
		input = strings.TrimPrefix(input, "@")
		return "https://twitter.com/" + input
	}
	if strings.HasPrefix(input, "http://") {
		input = strings.Replace(input, "http://", "https://", 1)
	}
	input = strings.Replace(input, "x.com/", "twitter.com/", 1)
	return input
}

func normalizeLinkedInURL(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	if !strings.Contains(input, "://") {
		return "https://www.linkedin.com/in/" + input
	}
	if strings.HasPrefix(input, "http://") {
		input = strings.Replace(input, "http://", "https://", 1)
	}
	return input
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
