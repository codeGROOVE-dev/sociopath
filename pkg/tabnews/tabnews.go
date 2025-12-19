// Package tabnews fetches TabNews user profile data.
package tabnews

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

const platform = "tabnews"

// Pre-compiled patterns for parsing TabNews data.
var (
	usernameRE   = regexp.MustCompile(`tabnews\.com\.br/([^/?#]+)`)
	tabcoinsRE   = regexp.MustCompile(`(\d+)\s*TabCoins?`)
	tabcashRE    = regexp.MustCompile(`(\d+(?:,\d+)?)\s*TabCash`)
	memberSinceRE = regexp.MustCompile(`Membro há (\d+) anos?`)
)

// platformInfo implements profile.Platform for TabNews.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeBlog }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() {
	profile.RegisterWithFetcher(platformInfo{}, fetchProfile)
}

// fetchProfile is the FetchFunc for TabNews profiles.
func fetchProfile(ctx context.Context, url string, cfg *profile.FetcherConfig) (*profile.Profile, error) {
	var opts []Option
	if cfg != nil {
		if cfg.Logger != nil {
			opts = append(opts, WithLogger(cfg.Logger))
		}
		if c, ok := cfg.Cache.(httpcache.Cacher); ok {
			opts = append(opts, WithHTTPCache(c))
		}
	}
	client, err := New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

// Match returns true if the URL is a TabNews profile URL.
func Match(url string) bool {
	lower := strings.ToLower(url)
	return strings.Contains(lower, "tabnews.com.br/") &&
		!strings.Contains(lower, "/conteudos") &&
		!strings.Contains(lower, "/comentarios") &&
		!strings.Contains(lower, "/classificados")
}

// AuthRequired returns false because TabNews profiles are public.
func AuthRequired() bool { return false }

// Client handles TabNews requests.
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

// New creates a TabNews client.
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

// Fetch retrieves a TabNews profile.
func (c *Client) Fetch(ctx context.Context, url string) (*profile.Profile, error) {
	username := extractUsername(url)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", url)
	}

	normalizedURL := fmt.Sprintf("https://www.tabnews.com.br/%s", username)
	c.logger.InfoContext(ctx, "fetching tabnews profile", "url", normalizedURL, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(string(body), normalizedURL, username, c.logger)
}

// userJSONData represents the embedded user data in TabNews pages.
type userJSONData struct {
	UserFound struct {
		ID        string `json:"id"`
		Username  string `json:"username"`
		TabCoins  int    `json:"tabcoins"`
		TabCash   int    `json:"tabcash"`
		Features  []string `json:"features"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	} `json:"userFound"`
}

func parseProfile(html, url, username string, logger *slog.Logger) (*profile.Profile, error) {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract name from title
	p.PageTitle = htmlutil.Title(html)
	if p.PageTitle != "" {
		name := strings.TrimSuffix(p.PageTitle, " - TabNews")
		name = strings.TrimSpace(name)
		p.DisplayName = name
	}
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	// Try to extract JSON data embedded in the page
	jsonPattern := regexp.MustCompile(`"userFound":\{[^}]+\}`)
	if match := jsonPattern.FindString(html); match != "" {
		// Wrap it in an object to parse
		wrapped := "{" + match + "}"
		var data userJSONData
		if err := json.Unmarshal([]byte(wrapped), &data); err == nil {
			if data.UserFound.TabCoins > 0 {
				p.Fields["tabcoins"] = fmt.Sprintf("%d", data.UserFound.TabCoins)
			}
			if data.UserFound.TabCash > 0 {
				p.Fields["tabcash"] = fmt.Sprintf("%d", data.UserFound.TabCash)
			}
			if data.UserFound.CreatedAt != "" {
				p.CreatedAt = data.UserFound.CreatedAt
			}
			if data.UserFound.UpdatedAt != "" {
				p.UpdatedAt = data.UserFound.UpdatedAt
			}
		} else {
			logger.Debug("failed to parse JSON data", "error", err)
		}
	}

	// Fallback: Extract from HTML if JSON parsing failed
	if p.Fields["tabcoins"] == "" {
		if m := tabcoinsRE.FindStringSubmatch(html); len(m) > 1 {
			p.Fields["tabcoins"] = m[1]
		}
	}
	if p.Fields["tabcash"] == "" {
		if m := tabcashRE.FindStringSubmatch(html); len(m) > 1 {
			p.Fields["tabcash"] = strings.ReplaceAll(m[1], ",", "")
		}
	}

	// Extract member since
	if m := memberSinceRE.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["member_years"] = m[1]
	}

	// Extract bio from meta description
	p.Bio = htmlutil.Description(html)

	// Extract social links from bio
	bioLines := strings.Split(p.Bio, "\n")
	for _, line := range bioLines {
		line = strings.TrimSpace(line)
		// Look for URLs in bio text
		urlPattern := regexp.MustCompile(`https?://[^\s]+`)
		urls := urlPattern.FindAllString(line, -1)
		for _, u := range urls {
			u = strings.TrimSuffix(u, ".")
			u = strings.TrimSuffix(u, ",")
			if !strings.Contains(u, "tabnews.com.br") {
				p.SocialLinks = append(p.SocialLinks, u)
			}
		}
	}

	// Also extract from HTML body
	for _, link := range htmlutil.SocialLinks(html) {
		if !strings.Contains(link, "tabnews.com.br") {
			alreadyAdded := false
			for _, existing := range p.SocialLinks {
				if existing == link {
					alreadyAdded = true
					break
				}
			}
			if !alreadyAdded {
				p.SocialLinks = append(p.SocialLinks, link)
			}
		}
	}

	return p, nil
}

func extractUsername(url string) string {
	if m := usernameRE.FindStringSubmatch(url); len(m) > 1 {
		username := m[1]
		// Remove any path segments
		username = strings.Split(username, "/")[0]
		return username
	}
	return ""
}
