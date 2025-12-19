// Package dicoding fetches Dicoding user profile data.
// Dicoding is Indonesia's largest developer learning platform.
package dicoding

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"

	"golang.org/x/net/html"
)

const platform = "dicoding"

// platformInfo implements profile.Platform for Dicoding.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)dicoding\.com/users/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Dicoding profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "dicoding.com/") {
		return false
	}
	// Exclude non-profile URLs
	excludePatterns := []string{
		"/academies/", "/events/", "/challenges/",
		"/blog/", "/courses/", "/jobs/", "/programs/",
	}
	for _, pattern := range excludePatterns {
		if strings.Contains(lower, pattern) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Dicoding profiles are public.
func AuthRequired() bool { return false }

// Client handles Dicoding requests.
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

// New creates a Dicoding client.
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

// Fetch retrieves a Dicoding profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching dicoding profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://www.dicoding.com/users/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "id,en-US;q=0.7,en;q=0.3")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	p, err := parseHTML(body, username, urlStr)
	if err != nil {
		return nil, err
	}

	c.logger.InfoContext(ctx, "parsed dicoding profile",
		"display_name", p.DisplayName,
		"avatar_url", p.AvatarURL,
		"bio", p.Bio,
		"fields_count", len(p.Fields),
		"posts_count", len(p.Posts),
		"badges_count", len(p.Badges))

	return p, nil
}

//nolint:gosmopolitan // Indonesian text for error detection
func parseHTML(body []byte, username, url string) (*profile.Profile, error) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse dicoding HTML: %w", err)
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
		Badges:   make(map[string]string),
	}

	var courses []profile.Post

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Extract from title tag
			if n.Data == "title" && n.FirstChild != nil {
				title := strings.TrimSpace(n.FirstChild.Data)
				// Format: "Name - Dicoding" or "Name"
				if strings.Contains(title, " - Dicoding") {
					parts := strings.Split(title, " - Dicoding")
					if len(parts) > 0 && parts[0] != "" {
						p.DisplayName = strings.TrimSpace(parts[0])
					}
				} else if strings.Contains(title, " | Dicoding") {
					parts := strings.Split(title, " | Dicoding")
					if len(parts) > 0 && parts[0] != "" {
						p.DisplayName = strings.TrimSpace(parts[0])
					}
				} else if title != "" && title != "Dicoding" {
					p.DisplayName = title
				}
			}

			// Extract meta description for bio
			if n.Data == "meta" {
				var name, content, property string
				for _, attr := range n.Attr {
					switch attr.Key {
					case "name":
						name = attr.Val
					case "property":
						property = attr.Val
					case "content":
						content = attr.Val
					}
				}
				if (name == "description" || property == "og:description") && content != "" && p.Bio == "" {
					p.Bio = strings.TrimSpace(content)
				}
				// Extract avatar from og:image
				if property == "og:image" && content != "" && p.AvatarURL == "" {
					p.AvatarURL = content
				}
			}

			// Extract avatar from img with profile/avatar classes
			if p.AvatarURL == "" {
				if hasClass(n, "profile-image") || hasClass(n, "avatar") || hasClass(n, "user-avatar") {
					if n.Data == "img" {
						if src := getAttribute(n, "src"); src != "" {
							p.AvatarURL = src
						}
					}
					if img := findElement(n, "img"); img != nil {
						if src := getAttribute(img, "src"); src != "" {
							p.AvatarURL = src
						}
					}
				}
			}

			// Extract location
			if hasClass(n, "location") || hasClass(n, "user-location") || hasClass(n, "address") {
				if text := getTextContent(n); text != "" {
					text = strings.TrimSpace(text)
					// Remove label if present
					if strings.Contains(text, ":") {
						parts := strings.Split(text, ":")
						if len(parts) > 1 {
							text = strings.TrimSpace(parts[1])
						}
					}
					if text != "" {
						p.Fields["location"] = text
					}
				}
			}

			// Extract XP points
			if hasClass(n, "xp") || hasClass(n, "experience") || hasClass(n, "points") {
				if text := getTextContent(n); text != "" {
					text = strings.TrimSpace(text)
					if strings.Contains(text, "XP") || strings.Contains(text, "xp") {
						// Remove "XP" suffix
						text = strings.ReplaceAll(text, "XP", "")
						text = strings.ReplaceAll(text, "xp", "")
						text = strings.TrimSpace(text)
					}
					if text != "" && text != "0" {
						p.Fields["xp"] = text
					}
				}
			}

			// Extract join year/date
			if hasClass(n, "join-date") || hasClass(n, "member-since") {
				if text := getTextContent(n); text != "" {
					text = strings.TrimSpace(text)
					// Parse year from text like "Bergabung sejak 2019"
					if strings.Contains(text, "sejak") {
						parts := strings.Split(text, "sejak")
						if len(parts) > 1 {
							year := strings.TrimSpace(parts[1])
							if len(year) == 4 {
								p.CreatedAt = year + "-01-01T00:00:00Z"
								p.Fields["join_year"] = year
							}
						}
					} else if len(text) == 4 {
						// Just a year
						p.CreatedAt = text + "-01-01T00:00:00Z"
						p.Fields["join_year"] = text
					}
				}
			}

			// Extract statistics - Academy count
			if hasClass(n, "academy") || hasClass(n, "academies") {
				extractStat(n, "academies", p)
			}

			// Extract statistics - Events count
			if hasClass(n, "event") || hasClass(n, "events") {
				extractStat(n, "events", p)
			}

			// Extract statistics - Challenges count
			if hasClass(n, "challenge") || hasClass(n, "challenges") {
				extractStat(n, "challenges", p)
			}

			// Extract statistics - Winning apps count
			if hasClass(n, "winning") || hasClass(n, "apps") {
				extractStat(n, "winning_apps", p)
			}

			// Extract course information
			if hasClass(n, "course") || hasClass(n, "class") {
				course := extractCourse(n)
				if course.Title != "" {
					courses = append(courses, course)
				}
			}

			// Extract achievements/badges
			if hasClass(n, "badge") || hasClass(n, "achievement") {
				badgeText := getTextContent(n)
				if badgeText != "" && !strings.Contains(badgeText, "\n\n") {
					badgeText = strings.TrimSpace(badgeText)
					if badgeText != "" {
						badgeKey := fmt.Sprintf("badge_%d", len(p.Badges)+1)
						p.Badges[badgeKey] = badgeText
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(doc)

	// Add collected courses
	if len(courses) > 0 {
		p.Posts = courses
	}

	// Default name if not found
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	// Check for not found BEFORE returning profile
	//nolint:gosmopolitan // Indonesian text for error detection
	bodyStr := string(body)
	if strings.Contains(bodyStr, "Pengguna tidak ditemukan") ||
		strings.Contains(bodyStr, "User not found") ||
		strings.Contains(bodyStr, "Halaman tidak ditemukan") ||
		strings.Contains(bodyStr, "Page not found") {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

// extractStat extracts a statistic value from a node and adds it to the profile.
func extractStat(n *html.Node, key string, p *profile.Profile) {
	text := getTextContent(n)
	text = strings.TrimSpace(text)

	// Look for numbers in the text
	for i := range len(text) {
		if text[i] >= '0' && text[i] <= '9' {
			// Extract consecutive digits
			var numBuilder strings.Builder
			for j := i; j < len(text); j++ {
				if text[j] >= '0' && text[j] <= '9' {
					numBuilder.WriteByte(text[j])
				} else if text[j] == ',' || text[j] == '.' {
					// Skip thousands separators
					continue
				} else {
					break
				}
			}
			numStr := numBuilder.String()
			if numStr != "" && numStr != "0" {
				// Only set if not already set
				if _, exists := p.Fields[key]; !exists {
					p.Fields[key] = numStr
				}
				return
			}
		}
	}
}

// extractCourse extracts course data from a course node.
func extractCourse(n *html.Node) profile.Post {
	course := profile.Post{Type: profile.PostTypeArticle}

	// Find title
	if titleNode := findElementWithClass(n, "course-title"); titleNode != nil {
		course.Title = strings.TrimSpace(getTextContent(titleNode))
	} else if titleNode := findElement(n, "h3"); titleNode != nil {
		course.Title = strings.TrimSpace(getTextContent(titleNode))
	} else if titleNode := findElement(n, "h4"); titleNode != nil {
		course.Title = strings.TrimSpace(getTextContent(titleNode))
	}

	// Find duration/hours
	if durationNode := findElementWithClass(n, "duration"); durationNode != nil {
		duration := strings.TrimSpace(getTextContent(durationNode))
		if duration != "" {
			course.Category = duration
		}
	}

	// Find rating
	if ratingNode := findElementWithClass(n, "rating"); ratingNode != nil {
		rating := strings.TrimSpace(getTextContent(ratingNode))
		if rating != "" && course.Category != "" {
			course.Category = course.Category + " • " + rating
		} else if rating != "" {
			course.Category = rating
		}
	}

	// Find link
	if link := findElement(n, "a"); link != nil {
		href := getAttribute(link, "href")
		if href != "" {
			if strings.HasPrefix(href, "/") {
				course.URL = "https://www.dicoding.com" + href
			} else if strings.HasPrefix(href, "http") {
				course.URL = href
			}
		}
	}

	return course
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
