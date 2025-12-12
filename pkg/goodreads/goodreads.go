// Package goodreads fetches Goodreads user profile data.
package goodreads

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

const platform = "goodreads"

var usernamePattern = regexp.MustCompile(`(?i)goodreads\.com/user/show/(\d+(?:-[a-zA-Z0-9_-]+)?)`)

// Match returns true if the URL is a Goodreads profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "goodreads.com/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Goodreads profiles are public.
func AuthRequired() bool { return false }

// Client handles Goodreads requests.
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

// New creates a Goodreads client.
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

// Fetch retrieves a Goodreads profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	userID := extractUserID(urlStr)
	if userID == "" {
		return nil, fmt.Errorf("could not extract user ID from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching goodreads profile", "url", urlStr, "user_id", userID)

	profileURL := fmt.Sprintf("https://www.goodreads.com/user/show/%s", userID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(body, userID, urlStr)
}

//nolint:gocognit // HTML parsing requires nested conditionals
func parseHTML(body []byte, userID, url string) (*profile.Profile, error) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse goodreads HTML: %w", err)
	}

	//nolint:varnamelen // p is idiomatic for profile
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: userID,
		Fields:   make(map[string]string),
	}

	// Extract data from meta tags
	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "meta" {
			var property, name, content string
			for _, attr := range n.Attr {
				switch attr.Key {
				case "property":
					property = attr.Val
				case "name":
					name = attr.Val
				case "content":
					content = attr.Val
				default:
					// Ignore other attributes
				}
			}

			switch property {
			case "og:title":
				if p.Name == "" && content != "" {
					p.Name = strings.TrimSpace(content)
				}
			case "og:description":
				if p.Bio == "" && content != "" {
					p.Bio = strings.TrimSpace(content)
				}
			case "og:image":
				if p.AvatarURL == "" && content != "" && strings.Contains(content, "photo.goodreads.com/users") {
					p.AvatarURL = content
				}
			case "profile:first_name":
				if content != "" {
					p.Fields["first_name"] = strings.TrimSpace(content)
				}
			case "profile:last_name":
				if content != "" {
					p.Fields["last_name"] = strings.TrimSpace(content)
				}
			default:
				// Ignore other properties
			}

			if name == "description" && p.Bio == "" && content != "" {
				p.Bio = strings.TrimSpace(content)
			}
		}

		// Extract title for location info
		if n.Type == html.ElementNode && n.Data == "title" && n.FirstChild != nil {
			title := n.FirstChild.Data
			// Parse: "Name (username) - Location (X books)"
			if idx := strings.Index(title, " - "); idx != -1 {
				locationPart := title[idx+3:]
				if parenIdx := strings.LastIndex(locationPart, " ("); parenIdx != -1 {
					location := strings.TrimSpace(locationPart[:parenIdx])
					if location != "" {
						p.Location = location
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(doc)

	// Fallback name from user ID
	if p.Name == "" {
		p.Name = userID
	}

	// Check for not found
	if p.Name == "" && p.Bio == "" {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func extractUserID(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
