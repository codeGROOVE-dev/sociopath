// Package vivaolinux fetches Viva o Linux user profile data.
package vivaolinux

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

const platform = "vivaolinux"

// Pre-compiled patterns for parsing Viva o Linux data.
var (
	usernameRE      = regexp.MustCompile(`vivaolinux\.com\.br/[~@]([^/?#]+)`)
	avatarRE        = regexp.MustCompile(`static\.vivaolinux\.com\.br/imagens/fotos/([^"']+\.(?:png|jpg|jpeg|gif))`)
	memberSinceRE   = regexp.MustCompile(`Membro desde:?\s*(\d+\s+de\s+\w+\s+de\s+\d+)`)
	lastLoginRE     = regexp.MustCompile(`Último login:?\s*([^<]+)`)
	locationRE      = regexp.MustCompile(`Localização:?\s*([^<]+)`)
	professionRE    = regexp.MustCompile(`Profissão:?\s*([^<]+)`)
	skillsRE        = regexp.MustCompile(`Habilidades:?\s*([^<]+)`)
	pointsRE        = regexp.MustCompile(`(\d+(?:,\d+)?)\s*(?:pontos?)`)
	articlesRE      = regexp.MustCompile(`(\d+)\s*(?:artigos?)`)
	tipsRE          = regexp.MustCompile(`(\d+)\s*(?:dicas?)`)
	scriptsRE       = regexp.MustCompile(`(\d+)\s*(?:scripts?)`)
	screenshotsRE   = regexp.MustCompile(`(\d+)\s*(?:screenshots?)`)
	forumPostsRE    = regexp.MustCompile(`(\d+)\s*(?:posts?\s+no\s+fórum)`)
	commentsRE      = regexp.MustCompile(`(\d+)\s*(?:comentários?)`)
	profileViewsRE  = regexp.MustCompile(`(\d+(?:,\d+)?)\s*(?:visualizações?)`)
	primaryDistroRE = regexp.MustCompile(`Distribuição principal:?\s*([^<]+)`)
)

// platformInfo implements profile.Platform for Viva o Linux.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() {
	profile.RegisterWithFetcher(platformInfo{}, fetchProfile)
}

// fetchProfile is the FetchFunc for Viva o Linux profiles.
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

// Match returns true if the URL is a Viva o Linux profile URL.
func Match(url string) bool {
	lower := strings.ToLower(url)
	return (strings.Contains(lower, "vivaolinux.com.br/~") ||
		strings.Contains(lower, "vivaolinux.com.br/@"))
}

// AuthRequired returns false because Viva o Linux profiles are public.
func AuthRequired() bool { return false }

// Client handles Viva o Linux requests.
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

// New creates a Viva o Linux client.
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

// Fetch retrieves a Viva o Linux profile.
func (c *Client) Fetch(ctx context.Context, url string) (*profile.Profile, error) {
	username := extractUsername(url)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", url)
	}

	// Normalize to tilde format
	normalizedURL := fmt.Sprintf("https://vivaolinux.com.br/~%s", username)
	c.logger.InfoContext(ctx, "fetching vivaolinux profile", "url", normalizedURL, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(string(body), normalizedURL, username)
}

func parseProfile(html, url, username string) (*profile.Profile, error) {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract name from title
	p.PageTitle = htmlutil.Title(html)
	if p.PageTitle != "" {
		// Clean up title - usually "Username - Viva o Linux" or similar
		name := p.PageTitle
		name = strings.TrimSuffix(name, " - Viva o Linux")
		name = strings.TrimSuffix(name, " - VOL")
		name = strings.TrimSpace(name)
		if name != "" && name != "Viva o Linux" {
			p.DisplayName = name
		}
	}
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	// Extract avatar
	if m := avatarRE.FindStringSubmatch(html); len(m) > 1 {
		p.AvatarURL = fmt.Sprintf("https://static.vivaolinux.com.br/imagens/fotos/%s", m[1])
	}

	// Extract member since
	if m := memberSinceRE.FindStringSubmatch(html); len(m) > 1 {
		p.CreatedAt = strings.TrimSpace(m[1])
	}

	// Extract last login
	if m := lastLoginRE.FindStringSubmatch(html); len(m) > 1 {
		p.UpdatedAt = strings.TrimSpace(m[1])
	}

	// Extract location
	if m := locationRE.FindStringSubmatch(html); len(m) > 1 {
		location := strings.TrimSpace(m[1])
		// Clean up common placeholder
		if location != "" && location != ".../.." {
			p.Location = location
		}
	}

	// Extract profession
	if m := professionRE.FindStringSubmatch(html); len(m) > 1 {
		profession := strings.TrimSpace(m[1])
		if profession != "" {
			p.Fields["profession"] = profession
		}
	}

	// Extract skills
	if m := skillsRE.FindStringSubmatch(html); len(m) > 1 {
		skills := strings.TrimSpace(m[1])
		if skills != "" && skills != "Nenhuma" && skills != "None" {
			p.Fields["skills"] = skills
		}
	}

	// Extract primary distribution
	if m := primaryDistroRE.FindStringSubmatch(html); len(m) > 1 {
		distro := strings.TrimSpace(m[1])
		if distro != "" {
			p.Fields["linux_distro"] = distro
		}
	}

	// Extract points/reputation
	if m := pointsRE.FindStringSubmatch(html); len(m) > 1 {
		points := strings.ReplaceAll(m[1], ",", "")
		p.Fields["points"] = points
	}

	// Extract article count
	if m := articlesRE.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["articles"] = m[1]
	}

	// Extract tips count
	if m := tipsRE.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["tips"] = m[1]
	}

	// Extract scripts count
	if m := scriptsRE.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["scripts"] = m[1]
	}

	// Extract screenshots count
	if m := screenshotsRE.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["screenshots"] = m[1]
	}

	// Extract forum posts count
	if m := forumPostsRE.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["forum_posts"] = m[1]
	}

	// Extract comments count
	if m := commentsRE.FindStringSubmatch(html); len(m) > 1 {
		p.Fields["comments"] = m[1]
	}

	// Extract profile views
	if m := profileViewsRE.FindStringSubmatch(html); len(m) > 1 {
		views := strings.ReplaceAll(m[1], ",", "")
		p.Fields["profile_views"] = views
	}

	// Extract bio
	p.Bio = htmlutil.Description(html)

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(html)
	var filtered []string
	for _, link := range p.SocialLinks {
		if !strings.Contains(link, "vivaolinux.com.br") {
			filtered = append(filtered, link)
		}
	}
	p.SocialLinks = filtered

	return p, nil
}

func extractUsername(url string) string {
	if m := usernameRE.FindStringSubmatch(url); len(m) > 1 {
		return m[1]
	}
	return ""
}
