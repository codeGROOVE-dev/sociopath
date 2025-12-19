// Package programmers fetches Programmers (Korean coding challenge platform) user profile data.
package programmers

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

const platform = "programmers"

// platformInfo implements profile.Platform for Programmers.
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

var usernamePattern = regexp.MustCompile(`(?i)programmers\.co\.kr/(?:profile|users?)/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Programmers profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "programmers.co.kr") &&
		(strings.Contains(lower, "/profile/") || strings.Contains(lower, "/user")) &&
		usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Programmers profiles are public.
func AuthRequired() bool { return false }

// Client handles Programmers requests.
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

// New creates a Programmers client.
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

// Fetch retrieves a Programmers user profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching programmers profile", "url", urlStr, "username", username)

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

	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Parse HTML for structured extraction
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		logger.Warn("failed to parse HTML", "error", err)
		// Continue with string-based extraction
	}

	// Extract name/title from title tag or page title
	title := htmlutil.Title(htmlStr)
	if title != "" {
		// Remove "Programmers" suffix if present
		title = strings.TrimSuffix(title, " - 프로그래머스")
		title = strings.TrimSuffix(title, " - Programmers")
		prof.DisplayName = strings.TrimSpace(title)
	}

	// Extract bio/description from meta description
	prof.Bio = htmlutil.Description(htmlStr)

	// Extract avatar/profile image
	if doc != nil {
		var extractAvatar func(*html.Node)
		extractAvatar = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "img" {
				src := getAttribute(n, "src")
				alt := getAttribute(n, "alt")
				class := getAttribute(n, "class")

				// Look for profile/avatar images
				if (strings.Contains(class, "profile") ||
					strings.Contains(class, "avatar") ||
					strings.Contains(alt, "profile") ||
					strings.Contains(alt, "프로필")) && src != "" && prof.AvatarURL == "" {
					prof.AvatarURL = src
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				extractAvatar(c)
			}
		}
		extractAvatar(doc)
	}

	// Extract stats (solved problems, ranking, etc.)
	if doc != nil {
		extractStats(doc, prof, logger)
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(htmlStr)

	// Filter out Programmers' own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "programmers.co.kr") {
			filtered = append(filtered, link)
		}
	}
	prof.SocialLinks = filtered

	// Use username as fallback for display name
	if prof.DisplayName == "" {
		prof.DisplayName = username
	}

	return prof, nil
}

func extractStats(doc *html.Node, prof *profile.Profile, logger *slog.Logger) {
	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			class := getAttribute(n, "class")

			// Look for stats elements (problems solved, ranking, points, etc.)
			if strings.Contains(class, "stat") ||
				strings.Contains(class, "score") ||
				strings.Contains(class, "rank") ||
				strings.Contains(class, "level") {

				text := getTextContent(n)
				text = strings.TrimSpace(text)

				// Try to identify what stat this is
				if strings.Contains(text, "문제") || strings.Contains(text, "solved") {
					prof.Fields["problems_solved"] = text
				} else if strings.Contains(text, "랭킹") || strings.Contains(text, "rank") {
					prof.Fields["ranking"] = text
				} else if strings.Contains(text, "레벨") || strings.Contains(text, "level") {
					prof.Fields["level"] = text
				} else if strings.Contains(text, "점수") || strings.Contains(text, "points") {
					prof.Fields["points"] = text
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(doc)
}

func getAttribute(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

func getTextContent(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var text strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		text.WriteString(getTextContent(c))
	}
	return text.String()
}

func extractUsername(urlStr string) string {
	// Extract username from programmers.co.kr/profile/{username} or /users/{username} pattern
	if matches := usernamePattern.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}
	return ""
}
