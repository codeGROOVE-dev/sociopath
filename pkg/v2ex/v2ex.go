// Package v2ex fetches V2EX user profile data.
package v2ex

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"

	"golang.org/x/net/html"
)

const platform = "v2ex"

// platformInfo implements profile.Platform for V2EX.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)v2ex\.com/member/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a V2EX profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "v2ex.com/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because V2EX profiles are public.
func AuthRequired() bool { return false }

// Client handles V2EX requests.
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

// New creates a V2EX client.
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

// Fetch retrieves a V2EX profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching v2ex profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://www.v2ex.com/member/%s", username)

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

	return parseHTML(body, username, urlStr)
}

//nolint:gocognit,gosmopolitan,nestif,varnamelen // HTML parsing requires nested conditionals, Chinese text for error detection
func parseHTML(body []byte, username, url string) (*profile.Profile, error) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse v2ex HTML: %w", err)
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Extract from title tag: "V2EX › Username"
			if n.Data == "title" && n.FirstChild != nil {
				title := strings.TrimSpace(n.FirstChild.Data)
				if strings.Contains(title, "V2EX ›") {
					parts := strings.Split(title, "›")
					if len(parts) > 1 {
						p.Name = strings.TrimSpace(parts[len(parts)-1])
					}
				}
			}

			// Extract avatar from shortcut icon or img with avatar class
			if n.Data == "link" {
				var rel, href string
				for _, attr := range n.Attr {
					switch attr.Key {
					case "rel":
						rel = attr.Val
					case "href":
						href = attr.Val
					default:
						// Ignore other attributes
					}
				}
				if rel == "shortcut icon" && strings.Contains(href, "avatar") {
					p.AvatarURL = href
				}
			}

			// Extract avatar from img tag
			if n.Data == "img" && hasClass(n, "avatar") && p.AvatarURL == "" {
				for _, attr := range n.Attr {
					if attr.Key == "src" && strings.Contains(attr.Val, "avatar") {
						p.AvatarURL = attr.Val
						break
					}
				}
			}

			// Extract bio/tagline from span with class "bigger"
			if n.Data == "span" && hasClass(n, "bigger") {
				if text := getTextContent(n); text != "" {
					p.Bio = strings.TrimSpace(text)
				}
			}

			// Extract join date and member number from gray span
			if n.Data == "span" && hasClass(n, "gray") {
				text := getTextContent(n)
				if strings.Contains(text, "号会员") {
					// Extract member number: "V2EX 第 1 号会员"
					if idx := strings.Index(text, "第"); idx >= 0 {
						numPart := text[idx+len("第"):]
						if endIdx := strings.Index(numPart, "号"); endIdx > 0 {
							p.Fields["member_number"] = strings.TrimSpace(numPart[:endIdx])
						}
					}
					// Extract join date: "加入于 2010-04-25"
					if idx := strings.Index(text, "加入于"); idx >= 0 {
						datePart := text[idx+len("加入于"):]
						datePart = strings.TrimSpace(datePart)
						if len(datePart) >= 10 {
							p.CreatedAt = datePart[:10]
						}
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(doc)

	// Default name if not found
	if p.Name == "" {
		p.Name = username
	}

	// Check for not found
	if strings.Contains(string(body), "这个用户不存在") || strings.Contains(string(body), "Member not found") {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func hasClass(n *html.Node, class string) bool {
	for _, attr := range n.Attr {
		if attr.Key == "class" {
			return slices.Contains(strings.Fields(attr.Val), class)
		}
	}
	return false
}

func getTextContent(n *html.Node) string {
	var sb strings.Builder
	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.TextNode {
			sb.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(n)
	return strings.TrimSpace(sb.String())
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
