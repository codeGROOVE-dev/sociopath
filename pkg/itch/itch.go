// Package itch fetches itch.io profile data.
package itch

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

const platform = "itch"

// platformInfo implements profile.Platform for itch.io.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeGaming }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)itch\.io/profile/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is an itch.io profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "itch.io/profile/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because itch.io profiles are public.
func AuthRequired() bool { return false }

// Client handles itch.io requests.
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

// New creates an itch.io client.
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

// Fetch retrieves an itch.io profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	profileURL := fmt.Sprintf("https://itch.io/profile/%s", username)
	c.logger.InfoContext(ctx, "fetching itch.io profile", "url", profileURL, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(string(body), username, profileURL)
}

func parseProfile(htmlContent, username, url string) (*profile.Profile, error) {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse itch.io HTML: %w", err)
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract page title
	p.PageTitle = htmlutil.Title(htmlContent)

	// Extract avatar from background-image style
	avatarPattern := regexp.MustCompile(`background-image:\s*url\(['"]?(https://img\.itch\.zone/[^'"()]+)['"]?\)`)
	if matches := avatarPattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		p.AvatarURL = matches[1]
	}

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Extract username from h2
			if n.Data == "h2" && p.DisplayName == "" {
				text := getTextContent(n)
				// Remove "Admin" or other badges
				if idx := strings.Index(text, "Admin"); idx != -1 {
					text = strings.TrimSpace(text[:idx])
				}
				if text != "" && !strings.Contains(text, "Recent") {
					p.DisplayName = strings.TrimSpace(text)
				}
			}

			// Extract stats
			if hasClass(n, "stat_box") {
				var value, label string
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == html.ElementNode {
						if hasClass(c, "stat_value") {
							value = strings.TrimSpace(getTextContent(c))
						} else if hasClass(c, "stat_label") {
							label = strings.TrimSpace(getTextContent(c))
						}
					}
				}
				if value != "" && label != "" {
					labelKey := strings.ToLower(strings.ReplaceAll(label, " ", "_"))
					p.Fields[labelKey] = value
				}
			}

			// Extract join date from abbr
			if n.Data == "abbr" && p.Fields["join_date"] == "" {
				if title := getAttribute(n, "title"); title != "" {
					p.Fields["join_date"] = title
				}
			}

			// Extract social links from user_links
			if hasClass(n, "link_group") {
				// Find the link element
				var linkURL string
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == html.ElementNode && c.Data == "a" {
						linkURL = getAttribute(c, "href")
						if linkURL != "" && !strings.Contains(linkURL, "itch.io") {
							p.SocialLinks = append(p.SocialLinks, linkURL)
						}
					}
				}
			}

			// Extract games from game_cell
			if hasClass(n, "game_cell") && !hasClass(n, "game_grid_widget") {
				game := extractGame(n)
				if game.Title != "" {
					p.Posts = append(p.Posts, game)
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(doc)

	// Default name if not found
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	// Validate we found minimal data
	if p.DisplayName == "" && len(p.Posts) == 0 {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func extractGame(n *html.Node) profile.Post {
	game := profile.Post{Type: profile.PostTypeRepository} // Games are similar to repos

	// Find game title
	if titleNode := findElementWithClass(n, "game_title"); titleNode != nil {
		if link := findElement(titleNode, "a"); link != nil {
			game.Title = strings.TrimSpace(getTextContent(link))
			game.URL = getAttribute(link, "href")
			// Ensure absolute URL
			if game.URL != "" && !strings.HasPrefix(game.URL, "http") {
				game.URL = "https://itch.io" + game.URL
			}
		}
	}

	// Extract description from game_text
	if textNode := findElementWithClass(n, "game_text"); textNode != nil {
		game.Content = strings.TrimSpace(getTextContent(textNode))
	}

	// Extract genre/category
	if genreNode := findElementWithClass(n, "game_genre"); genreNode != nil {
		game.Category = strings.TrimSpace(getTextContent(genreNode))
	}

	// Extract platform info
	if platformNode := findElementWithClass(n, "game_platform"); platformNode != nil {
		platformText := strings.TrimSpace(getTextContent(platformNode))
		if platformText != "" {
			if game.Content != "" {
				game.Content += "\nPlatform: " + platformText
			} else {
				game.Content = "Platform: " + platformText
			}
		}
	}

	return game
}

// Helper functions for HTML parsing.

func hasClass(n *html.Node, className string) bool {
	for _, attr := range n.Attr {
		if attr.Key == "class" && strings.Contains(attr.Val, className) {
			return true
		}
	}
	return false
}

func getAttribute(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

func findElement(n *html.Node, tagName string) *html.Node {
	if n.Type == html.ElementNode && n.Data == tagName {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if result := findElement(c, tagName); result != nil {
			return result
		}
	}
	return nil
}

func findElementWithClass(n *html.Node, className string) *html.Node {
	if n.Type == html.ElementNode && hasClass(n, className) {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if result := findElementWithClass(c, className); result != nil {
			return result
		}
	}
	return nil
}

func getTextContent(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var builder strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		builder.WriteString(getTextContent(c))
	}
	return builder.String()
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
