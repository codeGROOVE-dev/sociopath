// Package strava fetches Strava athlete profile data.
package strava

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

const platform = "strava"

// platformInfo implements profile.Platform for Strava.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var athleteIDPattern = regexp.MustCompile(`(?i)strava\.com/athletes/(\d+)`)

// Match returns true if the URL is a Strava athlete profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "strava.com/") {
		return false
	}
	return athleteIDPattern.MatchString(urlStr)
}

// AuthRequired returns false because Strava athlete profiles are publicly viewable.
func AuthRequired() bool { return false }

// Client handles Strava requests.
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

// New creates a Strava client.
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

// Fetch retrieves a Strava athlete profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	athleteID := extractAthleteID(urlStr)
	if athleteID == "" {
		return nil, fmt.Errorf("could not extract athlete ID from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching strava profile", "url", urlStr, "athlete_id", athleteID)

	profileURL := fmt.Sprintf("https://www.strava.com/athletes/%s", athleteID)

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

	return parseHTML(body, athleteID, urlStr)
}

//nolint:gocognit,nestif,varnamelen // HTML parsing requires nested conditionals
func parseHTML(body []byte, athleteID, url string) (*profile.Profile, error) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse strava HTML: %w", err)
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: athleteID,
		Fields:   make(map[string]string),
	}

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Extract from title tag: "Signup for free to see more about Name"
			if n.Data == "title" && n.FirstChild != nil {
				title := strings.TrimSpace(n.FirstChild.Data)
				// Format: "Signup for free to see more about Name"
				if strings.Contains(title, "see more about ") {
					if idx := strings.Index(title, "see more about "); idx >= 0 {
						p.Name = strings.TrimSpace(title[idx+len("see more about "):])
					}
				}
			}

			// Extract meta tags
			if n.Data == "meta" {
				var name, property, content string
				for _, attr := range n.Attr {
					switch attr.Key {
					case "name":
						name = attr.Val
					case "property":
						property = attr.Val
					case "content":
						content = attr.Val
					default:
						// Ignore other attributes
					}
				}
				if name == "description" && content != "" && p.Bio == "" {
					// Format: "Join Name and get inspired for your next workout"
					if strings.Contains(content, " and get inspired") {
						if idx := strings.Index(content, " and get inspired"); idx > 0 {
							joinPrefix := "Join "
							if strings.HasPrefix(content, joinPrefix) { //nolint:revive // nested conditionals for HTML parsing
								extractedName := content[len(joinPrefix):idx]
								if p.Name == "" {
									p.Name = extractedName
								}
							}
						}
					} else {
						p.Bio = strings.TrimSpace(content)
					}
				}
				if property == "og:image" && content != "" && p.AvatarURL == "" {
					// Only use if it's an actual avatar, not the Strava logo
					if !strings.Contains(content, "logo-strava") {
						p.AvatarURL = content
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
		p.Name = athleteID
	}

	// Check for not found - Strava returns 200 but shows a different page for invalid IDs
	if strings.Contains(string(body), "Page Not Found") || strings.Contains(string(body), "This athlete does not exist") {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func extractAthleteID(urlStr string) string {
	matches := athleteIDPattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
