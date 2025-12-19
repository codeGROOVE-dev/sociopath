// Package unixcom fetches Unix.com forum profile data.
package unixcom

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

const platform = "unixcom"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return false }

func init() { profile.RegisterWithFetcher(platformInfo{}, fetchProfile) }

var memberPattern = regexp.MustCompile(`unix\.com/member(?:_modal)?\.php\?u=(\d+)`)

func Match(urlStr string) bool {
	return (strings.Contains(urlStr, "unix.com/member.php") ||
		strings.Contains(urlStr, "unix.com/member_modal.php")) &&
		memberPattern.MatchString(urlStr)
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
	c.logger.InfoContext(ctx, "fetching unix.com profile", "url", urlStr)

	// Convert modal URL to regular member page for better data extraction
	fetchURL := strings.ReplaceAll(urlStr, "member_modal.php", "member.php")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, http.NoBody)
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

	// Extract username
	usernameRe := regexp.MustCompile(`<h1[^>]*>([^<]+)</h1>`)
	if matches := usernameRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Username = strings.TrimSpace(matches[1])
		p.DisplayName = p.Username
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
	if matches := avatarRe.FindStringSubmatch(html); len(matches) > 1 {
		p.AvatarURL = matches[1]
		if !strings.HasPrefix(p.AvatarURL, "http") {
			p.AvatarURL = "https://www.unix.com" + p.AvatarURL
		}
	}

	// Extract bio/about
	bioRe := regexp.MustCompile(`(?s)<div[^>]+id="about"[^>]*>(.*?)</div>`)
	if matches := bioRe.FindStringSubmatch(html); len(matches) > 1 {
		bio := htmlutil.StripTags(matches[1])
		p.Bio = strings.TrimSpace(bio)
	}

	// Extract post count
	postsRe := regexp.MustCompile(`(?i)Posts[:\s]*</strong>\s*([0-9,]+)`)
	if matches := postsRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["total_posts"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract join date
	joinRe := regexp.MustCompile(`(?i)Join(?:ed)?\s+Date[:\s]*</strong>\s*([^<]+)`)
	if matches := joinRe.FindStringSubmatch(html); len(matches) > 1 {
		p.CreatedAt = strings.TrimSpace(matches[1])
	}

	// Extract social links and emails
	p.SocialLinks = htmlutil.SocialLinks(html)
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
