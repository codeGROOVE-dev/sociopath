// Package imasters fetches iMasters Forum user profile data.
package imasters

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
)

const platform = "imasters"

// Pre-compiled patterns for parsing iMasters data.
var (
	usernameRE    = regexp.MustCompile(`forum\.imasters\.com\.br/profile/(\d+-[^/?#]+)`)
	avatarRE      = regexp.MustCompile(`uploads/profile/photo-thumb-(\d+)\.(?:jpg|png|gif)`)
	memberSinceRE = regexp.MustCompile(`Membro desde:?\s*([^<]+)`)
	locationRE    = regexp.MustCompile(`(?:Localização|Location):?\s*([^<]+)`)
	websiteRE     = regexp.MustCompile(`(?:Website|Site):?\s*<a[^>]+href=["']([^"']+)["']`)
	postCountRE   = regexp.MustCompile(`(\d+(?:,\d+)?)\s*(?:mensagens?|posts?|total items)`)
	reputationRE  = regexp.MustCompile(`Reputação:?\s*(\d+)`)
	followersRE   = regexp.MustCompile(`(\d+)\s*(?:Seguidores?|Followers?)`)
	viewsRE       = regexp.MustCompile(`(\d+(?:,\d+)?)\s*(?:visualizações|views)`)
)

// platformInfo implements profile.Platform for iMasters.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() {
	profile.RegisterWithFetcher(platformInfo{}, fetchProfile)
}

// fetchProfile is the FetchFunc for iMasters profiles.
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

// Match returns true if the URL is an iMasters profile URL.
func Match(url string) bool {
	lower := strings.ToLower(url)
	return strings.Contains(lower, "forum.imasters.com.br/profile/")
}

// AuthRequired returns false because iMasters profiles are public.
func AuthRequired() bool { return false }

// Client handles iMasters requests.
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

// New creates an iMasters client.
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

// Fetch retrieves an iMasters profile.
func (c *Client) Fetch(ctx context.Context, url string) (*profile.Profile, error) {
	profileSlug := extractProfileSlug(url)
	if profileSlug == "" {
		return nil, fmt.Errorf("could not extract profile slug from: %s", url)
	}

	normalizedURL := fmt.Sprintf("https://forum.imasters.com.br/profile/%s/", profileSlug)
	c.logger.InfoContext(ctx, "fetching imasters profile", "url", normalizedURL, "slug", profileSlug)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(string(body), normalizedURL, profileSlug)
}

func parseProfile(html, url, profileSlug string) (*profile.Profile, error) {
	// Extract username from slug (format: "12345-username")
	parts := strings.SplitN(profileSlug, "-", 2)
	username := profileSlug
	if len(parts) > 1 {
		username = parts[1]
	}

	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract name from title
	p.PageTitle = htmlutil.Title(html)
	if p.PageTitle != "" {
		// Clean up title - usually "Name - iMasters Forum" or similar
		name := p.PageTitle
		name = strings.TrimSuffix(name, " - iMasters")
		name = strings.TrimSuffix(name, " - Fórum iMasters")
		name = strings.TrimSpace(name)
		if name != "" && name != "iMasters" {
			p.DisplayName = name
		}
	}
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	// Extract avatar
	if m := avatarRE.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = fmt.Sprintf("https://forum.imasters.com.br/uploads/profile/photo-thumb-%s.jpg", m[1])
	}

	// Extract member since
	if m := memberSinceRE.FindStringSubmatch(html); len(m) > 1 {
		memberSince := strings.TrimSpace(m[1])
		p.CreatedAt = memberSince
	}

	// Extract location
	if m := locationRE.FindStringSubmatch(html); len(m) > 1 {
		p.Location = strings.TrimSpace(m[1])
	}

	// Extract website
	if m := websiteRE.FindStringSubmatch(html); len(m) > 1 {
		website := strings.TrimSpace(m[1])
		if website != "" && !strings.Contains(website, "imasters.com.br") {
			p.Website = website
		}
	}

	// Extract post count
	if m := postCountRE.FindStringSubmatch(html); len(m) > 1 {
		postCount := strings.ReplaceAll(m[1], ",", "")
		p.Fields["post_count"] = postCount
	}

	// Extract reputation
	if m := reputationRE.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["reputation"] = m[1]
	}

	// Extract followers
	if m := followersRE.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["followers"] = m[1]
	}

	// Extract profile views
	if m := viewsRE.FindStringSubmatch(html); len(m) > 1 {
		views := strings.ReplaceAll(m[1], ",", "")
		p.Fields["profile_views"] = views
	}

	// Extract bio/about from meta description or profile section
	p.Bio = htmlutil.Description(html)

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(html)
	var filtered []string
	for _, link := range p.SocialLinks {
		if !strings.Contains(link, "imasters.com.br") {
			filtered = append(filtered, link)
		}
	}
	p.SocialLinks = filtered

	return p, nil
}

func extractProfileSlug(url string) string {
	if m := usernameRE.FindStringSubmatch(url); len(m) > 1 {
		return m[1]
	}
	return ""
}
