// Package nexusmods fetches Nexus Mods user profile data.
package nexusmods

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
	"golang.org/x/net/html"
)

const platform = "nexusmods"

// platformInfo implements profile.Platform for Nexus Mods.
type platformInfo struct{}

func (platformInfo) Name() string {
	return platform
}

func (platformInfo) Type() profile.PlatformType {
	return profile.PlatformTypeOther
}

func (platformInfo) Match(url string) bool {
	return Match(url)
}

func (platformInfo) AuthRequired() bool {
	return AuthRequired()
}

func init() {
	profile.Register(platformInfo{})
}

// Match patterns for both old and new NexusMods sites
var usernamePattern = regexp.MustCompile(`(?i)(?:www\.|next\.)?nexusmods\.com/(?:users?|profile)/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Nexus Mods user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "nexusmods.com") &&
		(strings.Contains(lower, "/users/") ||
			strings.Contains(lower, "/user/") ||
			strings.Contains(lower, "/profile/")) &&
		usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Nexus Mods profiles are public.
func AuthRequired() bool { return false }

// Client handles Nexus Mods requests.
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

// New creates a Nexus Mods client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
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

// Fetch retrieves a Nexus Mods user profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching nexusmods profile", "url", urlStr, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, urlStr, username, c.logger)
}

func parseProfile(htmlBytes []byte, url, username string, logger *slog.Logger) (*profile.Profile, error) {
	htmlStr := string(htmlBytes)

	if htmlutil.IsNotFound(htmlStr) {
		return nil, profile.ErrProfileNotFound
	}

	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract title
	title := htmlutil.Title(htmlStr)
	if title != "" && !strings.Contains(title, "Nexus Mods") && !strings.Contains(title, "Profile") {
		prof.DisplayName = strings.TrimSpace(title)
	}

	// If no display name found, it might be a generic page
	if prof.DisplayName == "" {
		// Verify if this is actually a user profile by looking for other indicators
		if !strings.Contains(htmlStr, "Mods:") && !strings.Contains(htmlStr, "Downloads:") {
			return nil, profile.ErrProfileNotFound
		}
		prof.DisplayName = username
	}

	// Extract meta description for bio
	descPattern := regexp.MustCompile(`<meta\s+(?:name|property)="(?:description|og:description)"\s+content="([^"]+)"`)
	if m := descPattern.FindStringSubmatch(htmlStr); len(m) > 1 {
		prof.Bio = strings.TrimSpace(m[1])
	}

	// Extract avatar
	avatarPattern := regexp.MustCompile(`<img[^>]+(?:class="[^"]*avatar[^"]*"|id="[^"]*avatar[^"]*")[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(htmlStr); len(m) > 1 {
		avatarURL := m[1]
		// Make relative URLs absolute
		if strings.HasPrefix(avatarURL, "//") {
			avatarURL = "https:" + avatarURL
		} else if strings.HasPrefix(avatarURL, "/") {
			avatarURL = "https://www.nexusmods.com" + avatarURL
		}
		prof.AvatarURL = avatarURL
	}

	// Parse HTML for structured extraction
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err == nil {
		extractStats(doc, prof, logger)
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(htmlStr)

	// Filter out NexusMods' own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "nexusmods.com") {
			filtered = append(filtered, link)
		}
	}
	prof.SocialLinks = filtered

	return prof, nil
}

func extractStats(doc *html.Node, prof *profile.Profile, logger *slog.Logger) {
	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.TextNode {
			text := strings.TrimSpace(n.Data)

			// Look for stat patterns like "Mods: 42", "Downloads: 1.2M", "Endorsements: 500"
			if strings.Contains(text, "Mod") && strings.Contains(text, ":") {
				parts := strings.Split(text, ":")
				if len(parts) == 2 {
					prof.Fields["mods"] = strings.TrimSpace(parts[1])
				}
			} else if strings.Contains(text, "Download") && strings.Contains(text, ":") {
				parts := strings.Split(text, ":")
				if len(parts) == 2 {
					prof.Fields["downloads"] = strings.TrimSpace(parts[1])
				}
			} else if strings.Contains(text, "Endorsement") && strings.Contains(text, ":") {
				parts := strings.Split(text, ":")
				if len(parts) == 2 {
					prof.Fields["endorsements"] = strings.TrimSpace(parts[1])
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(doc)
}

func extractUsername(urlStr string) string {
	if matches := usernamePattern.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}
	return ""
}
