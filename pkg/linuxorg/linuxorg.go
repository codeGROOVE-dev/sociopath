// Package linuxorg fetches Linux.org Forums profile data.
package linuxorg

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "linuxorg"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return false }

func init() { profile.RegisterWithFetcher(platformInfo{}, fetchProfile) }

var memberPattern = regexp.MustCompile(`linux\.org/members/[^/]+\.(\d+)/?`)

func Match(urlStr string) bool {
	return strings.Contains(urlStr, "linux.org/members/") && memberPattern.MatchString(urlStr)
}

type Client struct {
	httpClient *http.Client
	cache      httpcache.Cacher
	logger     *slog.Logger
}

type Option func(*config)
type config struct {
	cache  httpcache.Cacher
	logger *slog.Logger
}

func WithHTTPCache(c httpcache.Cacher) Option { return func(cfg *config) { cfg.cache = c } }
func WithLogger(l *slog.Logger) Option        { return func(cfg *config) { cfg.logger = l } }

func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}
	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	c.logger.InfoContext(ctx, "fetching linux.org profile", "url", urlStr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, urlStr)
}

func parseProfile(body []byte, profileURL string) (*profile.Profile, error) {
	html := string(body)
	p := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Fields:   make(map[string]string),
	}

	// XenForo profile structure - Extract username from h1 or title
	usernameRe := regexp.MustCompile(`<h1[^>]+class="[^"]*username[^"]*"[^>]*>([^<]+)</h1>`)
	if matches := usernameRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Username = strings.TrimSpace(matches[1])
		p.DisplayName = p.Username
	}
	if p.Username == "" {
		titleRe := regexp.MustCompile(`<title>([^|<]+)\| Linux\.org</title>`)
		if matches := titleRe.FindStringSubmatch(html); len(matches) > 1 {
			p.Username = strings.TrimSpace(matches[1])
			p.DisplayName = p.Username
		}
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	if matches := avatarRe.FindStringSubmatch(html); len(matches) > 1 {
		p.AvatarURL = matches[1]
		if !strings.HasPrefix(p.AvatarURL, "http") {
			p.AvatarURL = "https://www.linux.org" + p.AvatarURL
		}
	}

	// Extract bio/about
	bioRe := regexp.MustCompile(`(?s)<div[^>]+class="[^"]*aboutSection[^"]*"[^>]*>(.*?)</div>`)
	if matches := bioRe.FindStringSubmatch(html); len(matches) > 1 {
		bio := htmlutil.StripTags(matches[1])
		p.Bio = strings.TrimSpace(bio)
	}

	// Extract location
	locationRe := regexp.MustCompile(`(?s)<dt>Location</dt>\s*<dd>([^<]+)</dd>`)
	if matches := locationRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Location = strings.TrimSpace(matches[1])
	}

	// Extract website
	websiteRe := regexp.MustCompile(`(?s)<dt>Website</dt>\s*<dd><a[^>]+href="([^"]+)"`)
	if matches := websiteRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Website = strings.TrimSpace(matches[1])
		p.SocialLinks = append(p.SocialLinks, p.Website)
	}

	// Extract join date
	joinRe := regexp.MustCompile(`(?s)<dt>Joined</dt>\s*<dd>(?:<time[^>]*>)?([^<]+)`)
	if matches := joinRe.FindStringSubmatch(html); len(matches) > 1 {
		p.CreatedAt = strings.TrimSpace(matches[1])
	}

	// Extract post count
	postsRe := regexp.MustCompile(`(?s)<dt>Messages</dt>\s*<dd>([0-9,]+)</dd>`)
	if matches := postsRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["total_posts"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract reaction score (likes)
	reactionRe := regexp.MustCompile(`(?s)<dt>Reaction score</dt>\s*<dd>([0-9,]+)</dd>`)
	if matches := reactionRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["reaction_score"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract trophy points
	trophyRe := regexp.MustCompile(`(?s)<dt>Trophy points</dt>\s*<dd>([0-9,]+)</dd>`)
	if matches := trophyRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["trophy_points"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract social links and emails
	for _, link := range htmlutil.SocialLinks(html) {
		found := false
		for _, existing := range p.SocialLinks {
			if existing == link {
				found = true
				break
			}
		}
		if !found {
			p.SocialLinks = append(p.SocialLinks, link)
		}
	}
	emails := htmlutil.EmailAddresses(html)
	if len(emails) > 0 {
		p.Fields["email"] = emails[0]
	}

	return p, nil
}

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
