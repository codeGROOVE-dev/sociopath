// Package gentoo fetches Gentoo Forums profile data.
package gentoo

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

const platform = "gentoo"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return false }

func init() { profile.RegisterWithFetcher(platformInfo{}, fetchProfile) }

var profilePattern = regexp.MustCompile(`forums\.gentoo\.org/(?:profile|memberlist)\.php\?mode=viewprofile&u=(\d+)`)

func Match(urlStr string) bool {
	return strings.Contains(urlStr, "forums.gentoo.org") &&
		(strings.Contains(urlStr, "profile.php") || strings.Contains(urlStr, "memberlist.php")) &&
		profilePattern.MatchString(urlStr)
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
	c.logger.InfoContext(ctx, "fetching gentoo forums profile", "url", urlStr)

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

	// phpBB 2.0 - Extract username from title
	titleRe := regexp.MustCompile(`<title>([^<]+) :: Gentoo Forums</title>`)
	if matches := titleRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Username = strings.TrimSpace(matches[1])
		p.DisplayName = p.Username
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`<img[^>]+src="([^"]+)"[^>]+alt="[^"]*[Aa]vatar[^"]*"`)
	if matches := avatarRe.FindStringSubmatch(html); len(matches) > 1 {
		p.AvatarURL = matches[1]
		if !strings.HasPrefix(p.AvatarURL, "http") {
			p.AvatarURL = "https://forums.gentoo.org" + p.AvatarURL
		}
	}

	// phpBB table-based layout
	locationRe := regexp.MustCompile(`(?s)<span[^>]+class="[^"]*gen[^"]*"[^>]*>Location:</span>.*?<td[^>]*>([^<]+)</td>`)
	if matches := locationRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Location = strings.TrimSpace(matches[1])
	}

	occupationRe := regexp.MustCompile(`(?s)<span[^>]+class="[^"]*gen[^"]*"[^>]*>Occupation:</span>.*?<td[^>]*>([^<]+)</td>`)
	if matches := occupationRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["occupation"] = strings.TrimSpace(matches[1])
	}

	interestsRe := regexp.MustCompile(`(?s)<span[^>]+class="[^"]*gen[^"]*"[^>]*>Interests:</span>.*?<td[^>]*>([^<]+)</td>`)
	if matches := interestsRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Bio = strings.TrimSpace(matches[1])
	}

	websiteRe := regexp.MustCompile(`(?s)<span[^>]+class="[^"]*gen[^"]*"[^>]*>Website:</span>.*?<a[^>]+href="([^"]+)"`)
	if matches := websiteRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Website = strings.TrimSpace(matches[1])
		p.SocialLinks = append(p.SocialLinks, p.Website)
	}

	joinedRe := regexp.MustCompile(`(?s)<span[^>]+class="[^"]*gen[^"]*"[^>]*>Joined:</span>.*?<td[^>]*>([^<]+)</td>`)
	if matches := joinedRe.FindStringSubmatch(html); len(matches) > 1 {
		p.CreatedAt = strings.TrimSpace(matches[1])
	}

	postsRe := regexp.MustCompile(`(?s)<span[^>]+class="[^"]*gen[^"]*"[^>]*>Total posts:</span>.*?<td[^>]*>([0-9,]+)`)
	if matches := postsRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["total_posts"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract IM handles
	extractIMHandle(html, "ICQ", p)
	extractIMHandle(html, "AIM", p)
	extractIMHandle(html, "MSN", p)
	extractIMHandle(html, "Yahoo", p)
	extractIMHandle(html, "Jabber", p)

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

func extractIMHandle(html, service string, p *profile.Profile) {
	re := regexp.MustCompile(fmt.Sprintf(`(?s)<span[^>]+class="[^"]*gen[^"]*"[^>]*>%s:</span>.*?<td[^>]*>([^<]+)</td>`, service))
	if matches := re.FindStringSubmatch(html); len(matches) > 1 {
		handle := strings.TrimSpace(matches[1])
		if handle != "" && handle != "-" && handle != "N/A" {
			p.Fields[strings.ToLower(service)] = handle
		}
	}
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
