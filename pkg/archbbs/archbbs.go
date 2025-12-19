// Package archbbs fetches Arch Linux BBS profile data.
package archbbs

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

const platform = "archbbs"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return false }

func init() { profile.RegisterWithFetcher(platformInfo{}, fetchProfile) }

var profilePattern = regexp.MustCompile(`bbs\.archlinux\.org/profile\.php\?id=(\d+)`)

func Match(urlStr string) bool {
	return strings.Contains(urlStr, "bbs.archlinux.org/profile.php") && profilePattern.MatchString(urlStr)
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
	c.logger.InfoContext(ctx, "fetching arch bbs profile", "url", urlStr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

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

	// FluxBB profile structure
	usernameRe := regexp.MustCompile(`<h2><span>([^<]+)</span></h2>`)
	if matches := usernameRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Username = strings.TrimSpace(matches[1])
		p.DisplayName = p.Username
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`<img[^>]+src="([^"]+)"[^>]+alt="(?:[^"]*avatar[^"]*)"`)
	if matches := avatarRe.FindStringSubmatch(html); len(matches) > 1 {
		p.AvatarURL = matches[1]
		if !strings.HasPrefix(p.AvatarURL, "http") {
			p.AvatarURL = "https://bbs.archlinux.org" + p.AvatarURL
		}
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

	// Extract registered date
	registeredRe := regexp.MustCompile(`(?s)<dt>Registered</dt>\s*<dd>([^<]+)</dd>`)
	if matches := registeredRe.FindStringSubmatch(html); len(matches) > 1 {
		p.CreatedAt = strings.TrimSpace(matches[1])
	}

	// Extract post count
	postsRe := regexp.MustCompile(`(?s)<dt>Posts</dt>\s*<dd>([0-9,]+)</dd>`)
	if matches := postsRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["total_posts"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract signature
	signatureRe := regexp.MustCompile(`(?s)<div[^>]+class="[^"]*sig-content[^"]*"[^>]*>(.*?)</div>`)
	if matches := signatureRe.FindStringSubmatch(html); len(matches) > 1 {
		signature := htmlutil.StripTags(matches[1])
		if len(signature) > 0 && len(signature) < 500 {
			p.Fields["signature"] = strings.TrimSpace(signature)
		}
	}

	// Extract additional social links and emails
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
