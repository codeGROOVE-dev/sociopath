// Package sociopath provides a unified API for fetching social media profiles.
//
// Basic usage:
//
//	profile, err := sociopath.Fetch(ctx, "https://mastodon.social/@johndoe")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(profile.Name, profile.Bio)
//
// For platforms requiring authentication (LinkedIn, Twitter):
//
//	profile, err := sociopath.Fetch(ctx, "https://linkedin.com/in/johndoe",
//	    sociopath.WithCookies(map[string]string{"li_at": "...", "JSESSIONID": "..."}))
//
// Or use platform packages directly:
//
//	import "github.com/codeGROOVE-dev/sociopath/pkg/linkedin"
//	client, _ := linkedin.New(ctx, linkedin.WithBrowserCookies())
//	profile, _ := client.Fetch(ctx, "https://linkedin.com/in/johndoe")
package sociopath

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/codeGROOVE-dev/sociopath/pkg/bilibili"
	"github.com/codeGROOVE-dev/sociopath/pkg/bluesky"
	"github.com/codeGROOVE-dev/sociopath/pkg/codeberg"
	"github.com/codeGROOVE-dev/sociopath/pkg/devto"
	"github.com/codeGROOVE-dev/sociopath/pkg/generic"
	"github.com/codeGROOVE-dev/sociopath/pkg/github"
	"github.com/codeGROOVE-dev/sociopath/pkg/google"
	"github.com/codeGROOVE-dev/sociopath/pkg/gravatar"
	"github.com/codeGROOVE-dev/sociopath/pkg/guess"
	"github.com/codeGROOVE-dev/sociopath/pkg/habr"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/instagram"
	"github.com/codeGROOVE-dev/sociopath/pkg/linkedin"
	"github.com/codeGROOVE-dev/sociopath/pkg/linktree"
	"github.com/codeGROOVE-dev/sociopath/pkg/mailru"
	"github.com/codeGROOVE-dev/sociopath/pkg/mastodon"
	"github.com/codeGROOVE-dev/sociopath/pkg/medium"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
	"github.com/codeGROOVE-dev/sociopath/pkg/reddit"
	"github.com/codeGROOVE-dev/sociopath/pkg/stackoverflow"
	"github.com/codeGROOVE-dev/sociopath/pkg/substack"
	"github.com/codeGROOVE-dev/sociopath/pkg/tiktok"
	"github.com/codeGROOVE-dev/sociopath/pkg/twitter"
	"github.com/codeGROOVE-dev/sociopath/pkg/vkontakte"
	"github.com/codeGROOVE-dev/sociopath/pkg/weibo"
	"github.com/codeGROOVE-dev/sociopath/pkg/youtube"
)

type (
	// Profile re-exports profile.Profile for convenience.
	Profile = profile.Profile
	// HTTPCache re-exports httpcache.Cache for convenience.
	HTTPCache = httpcache.Cache
)

// Re-export common errors.
var (
	ErrAuthRequired    = profile.ErrAuthRequired
	ErrNoCookies       = profile.ErrNoCookies
	ErrProfileNotFound = profile.ErrProfileNotFound
	ErrRateLimited     = profile.ErrRateLimited
)

// Option configures a Fetch call.
type Option func(*config)

//nolint:govet // fieldalignment: intentional layout for readability
type config struct {
	cache          httpcache.Cacher
	cookies        map[string]string
	logger         *slog.Logger
	githubToken    string
	browserCookies bool
	emailHints     []string // Email addresses to associate with profiles
}

// WithCookies sets explicit cookie values for authenticated platforms.
func WithCookies(cookies map[string]string) Option {
	return func(c *config) { c.cookies = cookies }
}

// WithBrowserCookies enables reading cookies from browser stores.
func WithBrowserCookies() Option {
	return func(c *config) { c.browserCookies = true }
}

// WithHTTPCache sets the HTTP cache for responses.
func WithHTTPCache(httpCache httpcache.Cacher) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// WithGitHubToken sets the GitHub API token for authenticated requests.
func WithGitHubToken(token string) Option {
	return func(c *config) { c.githubToken = token }
}

// WithEmailHints provides email addresses to associate with profiles.
// These emails are stored in Fields["email_hints"] and can be used for
// additional lookups (Gravatar, Google GAIA ID resolution, etc.).
func WithEmailHints(emails ...string) Option {
	return func(c *config) { c.emailHints = append(c.emailHints, emails...) }
}

// Fetch retrieves a profile from the given URL.
// The platform is automatically detected from the URL.
func Fetch(ctx context.Context, url string, opts ...Option) (*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	var p *profile.Profile
	var err error

	// Try each platform's Match function in order of specificity
	// Note: Order matters! More specific patterns should come before generic ones.
	// TikTok must come before Mastodon because Mastodon matches /@username pattern.
	// Substack must come before generic because it has specific domain pattern.
	switch {
	case linkedin.Match(url):
		p, err = fetchLinkedIn(ctx, url, cfg)
	case twitter.Match(url):
		p, err = fetchTwitter(ctx, url, cfg)
	case linktree.Match(url):
		p, err = fetchLinktree(ctx, url, cfg)
	case github.Match(url):
		p, err = fetchGitHub(ctx, url, cfg)
	case medium.Match(url):
		p, err = fetchMedium(ctx, url, cfg)
	case reddit.Match(url):
		p, err = fetchReddit(ctx, url, cfg)
	case youtube.Match(url):
		p, err = fetchYouTube(ctx, url, cfg)
	case substack.Match(url):
		p, err = fetchSubstack(ctx, url, cfg)
	case bilibili.Match(url):
		p, err = fetchBilibili(ctx, url, cfg)
	case codeberg.Match(url):
		p, err = fetchCodeberg(ctx, url, cfg)
	case bluesky.Match(url):
		p, err = fetchBlueSky(ctx, url, cfg)
	case devto.Match(url):
		p, err = fetchDevTo(ctx, url, cfg)
	case stackoverflow.Match(url):
		p, err = fetchStackOverflow(ctx, url, cfg)
	case habr.Match(url):
		p, err = fetchHabr(ctx, url, cfg)
	case instagram.Match(url):
		p, err = fetchInstagram(ctx, url, cfg)
	case tiktok.Match(url):
		p, err = fetchTikTok(ctx, url, cfg)
	case vkontakte.Match(url):
		p, err = fetchVKontakte(ctx, url, cfg)
	case weibo.Match(url):
		p, err = fetchWeibo(ctx, url, cfg)
	case mailru.Match(url):
		p, err = fetchMailRu(ctx, url, cfg)
	case google.Match(url):
		p, err = fetchGoogle(ctx, url, cfg)
	case gravatar.Match(url):
		p, err = fetchGravatar(ctx, url, cfg)
	case mastodon.Match(url):
		p, err = fetchMastodon(ctx, url, cfg)
	default:
		p, err = fetchGeneric(ctx, url, cfg)
	}

	// Apply email hints to the profile
	if err == nil && p != nil && len(cfg.emailHints) > 0 {
		applyEmailHints(p, cfg.emailHints)
	}

	return p, err
}

// applyEmailHints adds email addresses to the profile's Fields.
func applyEmailHints(p *profile.Profile, emails []string) {
	if p.Fields == nil {
		p.Fields = make(map[string]string)
	}
	for i, email := range emails {
		key := "email"
		if i > 0 {
			key = fmt.Sprintf("email_%d", i+1)
		}
		// Don't overwrite existing email fields
		if _, exists := p.Fields[key]; !exists {
			p.Fields[key] = email
		}
	}
}

func fetchLinkedIn(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []linkedin.Option
	if len(cfg.cookies) > 0 {
		opts = append(opts, linkedin.WithCookies(cfg.cookies))
	}
	if cfg.browserCookies {
		opts = append(opts, linkedin.WithBrowserCookies())
	}
	if cfg.cache != nil {
		opts = append(opts, linkedin.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, linkedin.WithLogger(cfg.logger))
	}

	client, err := linkedin.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchTwitter(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []twitter.Option
	if len(cfg.cookies) > 0 {
		opts = append(opts, twitter.WithCookies(cfg.cookies))
	}
	if cfg.browserCookies {
		opts = append(opts, twitter.WithBrowserCookies())
	}
	if cfg.cache != nil {
		opts = append(opts, twitter.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, twitter.WithLogger(cfg.logger))
	}

	client, err := twitter.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchMastodon(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []mastodon.Option
	if cfg.cache != nil {
		opts = append(opts, mastodon.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, mastodon.WithLogger(cfg.logger))
	}

	client, err := mastodon.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchBlueSky(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []bluesky.Option
	if cfg.cache != nil {
		opts = append(opts, bluesky.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, bluesky.WithLogger(cfg.logger))
	}

	client, err := bluesky.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchDevTo(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []devto.Option
	if cfg.cache != nil {
		opts = append(opts, devto.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, devto.WithLogger(cfg.logger))
	}

	client, err := devto.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchStackOverflow(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []stackoverflow.Option
	if cfg.cache != nil {
		opts = append(opts, stackoverflow.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, stackoverflow.WithLogger(cfg.logger))
	}

	client, err := stackoverflow.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHabr(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []habr.Option
	if cfg.cache != nil {
		opts = append(opts, habr.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, habr.WithLogger(cfg.logger))
	}

	client, err := habr.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchInstagram(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []instagram.Option
	if len(cfg.cookies) > 0 {
		opts = append(opts, instagram.WithCookies(cfg.cookies))
	}

	client, err := instagram.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchTikTok(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []tiktok.Option
	if len(cfg.cookies) > 0 {
		opts = append(opts, tiktok.WithCookies(cfg.cookies))
	}
	if cfg.cache != nil {
		opts = append(opts, tiktok.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, tiktok.WithLogger(cfg.logger))
	}

	client, err := tiktok.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchVKontakte(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []vkontakte.Option
	if len(cfg.cookies) > 0 {
		opts = append(opts, vkontakte.WithCookies(cfg.cookies))
	}
	if cfg.cache != nil {
		opts = append(opts, vkontakte.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, vkontakte.WithLogger(cfg.logger))
	}

	client, err := vkontakte.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchWeibo(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []weibo.Option
	if len(cfg.cookies) > 0 {
		opts = append(opts, weibo.WithCookies(cfg.cookies))
	}
	if cfg.browserCookies {
		opts = append(opts, weibo.WithBrowserCookies())
	}
	if cfg.cache != nil {
		opts = append(opts, weibo.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, weibo.WithLogger(cfg.logger))
	}

	client, err := weibo.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchLinktree(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []linktree.Option
	if cfg.cache != nil {
		opts = append(opts, linktree.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, linktree.WithLogger(cfg.logger))
	}

	client, err := linktree.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchGitHub(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []github.Option
	if cfg.cache != nil {
		opts = append(opts, github.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, github.WithLogger(cfg.logger))
	}
	if cfg.githubToken != "" {
		opts = append(opts, github.WithToken(cfg.githubToken))
	}

	client, err := github.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchGoogle(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []google.Option
	if cfg.cache != nil {
		opts = append(opts, google.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, google.WithLogger(cfg.logger))
	}

	client, err := google.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchGravatar(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []gravatar.Option
	if cfg.cache != nil {
		opts = append(opts, gravatar.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, gravatar.WithLogger(cfg.logger))
	}

	client, err := gravatar.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchMailRu(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []mailru.Option
	if cfg.cache != nil {
		opts = append(opts, mailru.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, mailru.WithLogger(cfg.logger))
	}

	client, err := mailru.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchMedium(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []medium.Option
	if cfg.cache != nil {
		opts = append(opts, medium.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, medium.WithLogger(cfg.logger))
	}

	client, err := medium.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchReddit(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []reddit.Option
	if cfg.cache != nil {
		opts = append(opts, reddit.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, reddit.WithLogger(cfg.logger))
	}

	client, err := reddit.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchYouTube(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []youtube.Option
	if cfg.cache != nil {
		opts = append(opts, youtube.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, youtube.WithLogger(cfg.logger))
	}

	client, err := youtube.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchSubstack(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []substack.Option
	if cfg.cache != nil {
		opts = append(opts, substack.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, substack.WithLogger(cfg.logger))
	}

	client, err := substack.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchBilibili(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []bilibili.Option
	if cfg.cache != nil {
		opts = append(opts, bilibili.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, bilibili.WithLogger(cfg.logger))
	}

	client, err := bilibili.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchCodeberg(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []codeberg.Option
	if cfg.cache != nil {
		opts = append(opts, codeberg.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, codeberg.WithLogger(cfg.logger))
	}

	client, err := codeberg.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchGeneric(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []generic.Option
	if cfg.cache != nil {
		opts = append(opts, generic.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, generic.WithLogger(cfg.logger))
	}

	client, err := generic.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

// FetchRecursive fetches a profile and recursively fetches all social links found.
// It returns all discovered profiles, avoiding duplicates by tracking visited URLs.
// Only links that match known social media platforms are followed.
// For platforms with single-account-per-person assumption (GitHub, LinkedIn, Twitter, etc.),
// it skips recursing into additional profiles from the same platform.
func FetchRecursive(ctx context.Context, url string, opts ...Option) ([]*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	visited := make(map[string]bool)
	var profiles []*profile.Profile
	initialPlatform := "" // Track the platform we started from

	type queueItem struct {
		url   string
		depth int
	}
	const maxDepth = 3
	const maxLinksPerPage = 8

	queue := []queueItem{{url: url, depth: 0}}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		normalizedURL := normalizeURL(item.url)
		if visited[normalizedURL] {
			continue
		}
		visited[normalizedURL] = true

		cfg.logger.InfoContext(ctx, "fetching profile", "url", item.url, "depth", item.depth, "visited", len(visited))

		p, err := Fetch(ctx, item.url, opts...)
		if err != nil {
			// For auth-required platforms, try generic parser on any error (except LinkedIn)
			// LinkedIn's generic HTML contains dozens of "People Also Viewed" links that cause runaway crawling
			tryGeneric := (twitter.Match(item.url) || instagram.Match(item.url) ||
				tiktok.Match(item.url) || vkontakte.Match(item.url)) && !linkedin.Match(item.url)

			if !tryGeneric {
				cfg.logger.WarnContext(ctx, "failed to fetch profile", "url", item.url, "error", err)
				// If it's an auth-related error, add a stub profile with the error
				if errors.Is(err, profile.ErrNoCookies) || errors.Is(err, profile.ErrAuthRequired) {
					profiles = append(profiles, &profile.Profile{
						Platform: PlatformForURL(item.url),
						URL:      item.url,
						Error:    "login required",
					})
				}
				continue
			}

			cfg.logger.InfoContext(ctx, "fetch failed, trying generic parser", "url", item.url, "error", err)
			p, err = fetchGeneric(ctx, item.url, cfg)
			if err != nil {
				cfg.logger.WarnContext(ctx, "generic fetch also failed", "url", item.url, "error", err)
				continue
			}
		}
		profiles = append(profiles, p)

		// Remember the platform we started from (depth 0)
		if item.depth == 0 {
			initialPlatform = p.Platform
		}

		// Don't crawl further if we've hit max depth
		if item.depth >= maxDepth {
			continue
		}

		// From generic pages, only follow known social platform links to avoid runaway crawling
		onlyKnownPlatforms := p.Platform == "generic"

		// Collect links to queue, then limit
		var linksToQueue []string

		// Queue social links for crawling
		for _, link := range p.SocialLinks {
			if !visited[normalizeURL(link)] && isValidProfileURL(link) {
				// Skip links that are the same platform as our initial URL (single-account-per-person platforms)
				if isSingleAccountPlatform(initialPlatform) && platformMatches(link, initialPlatform) {
					continue
				}

				// For generic pages, only follow if it's a known social platform or same-domain contact/about page
				if !onlyKnownPlatforms || isSocialPlatform(link) || isSameDomainContactPage(link, item.url) {
					linksToQueue = append(linksToQueue, link)
				}
			}
		}

		// Also queue website if present
		if p.Website != "" && !visited[normalizeURL(p.Website)] {
			linksToQueue = append(linksToQueue, p.Website)
		}

		// Queue links from Fields map (sorted for deterministic iteration order)
		keys := make([]string, 0, len(p.Fields))
		for k := range p.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := p.Fields[k]
			if isLikelySocialURL(k, v) && !visited[normalizeURL(v)] {
				linksToQueue = append(linksToQueue, v)
			}
		}

		// Limit links per page to avoid explosion
		if len(linksToQueue) > maxLinksPerPage {
			linksToQueue = linksToQueue[:maxLinksPerPage]
		}

		for _, link := range linksToQueue {
			queue = append(queue, queueItem{url: link, depth: item.depth + 1})
		}
	}

	return profiles, nil
}

// isValidProfileURL filters out URLs that are not actual user profiles.
// Delegates to platform-specific validators when available.
func isValidProfileURL(urlStr string) bool {
	// Use platform-specific validation for Twitter/X
	if twitter.Match(urlStr) {
		return twitter.IsValidProfileURL(urlStr)
	}

	// Other platforms: no filtering for now
	return true
}

// isSocialPlatform returns true if the URL matches a known social media platform.
func isSocialPlatform(url string) bool {
	return linkedin.Match(url) ||
		twitter.Match(url) ||
		linktree.Match(url) ||
		github.Match(url) ||
		codeberg.Match(url) ||
		google.Match(url) ||
		gravatar.Match(url) ||
		mailru.Match(url) ||
		medium.Match(url) ||
		reddit.Match(url) ||
		youtube.Match(url) ||
		substack.Match(url) ||
		weibo.Match(url) ||
		strings.Contains(strings.ToLower(url), "zhihu.com") ||
		bilibili.Match(url) ||
		bluesky.Match(url) ||
		devto.Match(url) ||
		stackoverflow.Match(url) ||
		habr.Match(url) ||
		instagram.Match(url) ||
		tiktok.Match(url) ||
		vkontakte.Match(url) ||
		mastodon.Match(url)
}

// isSameDomainContactPage returns true if the link is a contact/about page on the same domain as baseURL.
func isSameDomainContactPage(link, baseURL string) bool {
	linkLower := strings.ToLower(link)
	baseLower := strings.ToLower(baseURL)

	// Extract domains (simple approach - get hostname)
	getDomain := func(url string) string {
		url = strings.TrimPrefix(url, "https://")
		url = strings.TrimPrefix(url, "http://")
		url = strings.TrimPrefix(url, "www.")
		if idx := strings.Index(url, "/"); idx >= 0 {
			url = url[:idx]
		}
		return url
	}

	linkDomain := getDomain(linkLower)
	baseDomain := getDomain(baseLower)

	// Only follow if same domain
	if linkDomain != baseDomain {
		return false
	}

	// Check if it looks like a contact/about page
	contactPaths := []string{"/about", "/contact", "/links", "/connect", "/socials"}
	for _, path := range contactPaths {
		if strings.Contains(linkLower, path) {
			return true
		}
	}

	return false
}

// normalizeURL normalizes a URL for deduplication (removes trailing slash, lowercases host).
func normalizeURL(url string) string {
	url = strings.TrimSuffix(url, "/")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "www.")
	return strings.ToLower(url)
}

// isLikelySocialURL checks if a field value looks like a social media URL worth crawling.
func isLikelySocialURL(key, value string) bool {
	if !strings.HasPrefix(value, "http") {
		return false
	}
	// Known social field keys
	socialKeys := []string{"twitter", "linkedin", "github", "instagram", "youtube", "tiktok", "mastodon", "bluesky", "website"}
	for _, k := range socialKeys {
		if strings.Contains(strings.ToLower(key), k) {
			return true
		}
	}
	return false
}

// isSingleAccountPlatform returns true for platforms where users typically have a single account.
func isSingleAccountPlatform(platform string) bool {
	switch platform {
	case "github", "codeberg", "linkedin", "twitter", "reddit", "youtube",
		"stackoverflow", "bluesky", "mastodon", "medium",
		"instagram", "tiktok", "vkontakte":
		return true
	default:
		return false
	}
}

// PlatformForURL returns the platform name for a URL, or "generic" if unknown.
// This uses the same matching logic as Fetch() to ensure consistency.
func PlatformForURL(url string) string {
	switch {
	case linkedin.Match(url):
		return "linkedin"
	case twitter.Match(url):
		return "twitter"
	case linktree.Match(url):
		return "linktree"
	case github.Match(url):
		return "github"
	case codeberg.Match(url):
		return "codeberg"
	case google.Match(url):
		return "google"
	case medium.Match(url):
		return "medium"
	case reddit.Match(url):
		return "reddit"
	case youtube.Match(url):
		return "youtube"
	case substack.Match(url):
		return "substack"
	case bilibili.Match(url):
		return "bilibili"
	case bluesky.Match(url):
		return "bluesky"
	case devto.Match(url):
		return "devto"
	case stackoverflow.Match(url):
		return "stackoverflow"
	case habr.Match(url):
		return "habr"
	case instagram.Match(url):
		return "instagram"
	case tiktok.Match(url):
		return "tiktok"
	case vkontakte.Match(url):
		return "vkontakte"
	case weibo.Match(url):
		return "weibo"
	case mastodon.Match(url):
		return "mastodon"
	case gravatar.Match(url):
		return "gravatar"
	case mailru.Match(url):
		return "mailru"
	default:
		return "generic"
	}
}

// platformMatches checks if a URL matches the given platform name.
func platformMatches(url, platform string) bool {
	switch platform {
	case "github":
		return github.Match(url)
	case "codeberg":
		return codeberg.Match(url)
	case "google":
		return google.Match(url)
	case "linkedin":
		return linkedin.Match(url)
	case "twitter":
		return twitter.Match(url)
	case "reddit":
		return reddit.Match(url)
	case "youtube":
		return youtube.Match(url)
	case "stackoverflow":
		return stackoverflow.Match(url)
	case "bluesky":
		return bluesky.Match(url)
	case "mastodon":
		return mastodon.Match(url)
	case "medium":
		return medium.Match(url)
	case "instagram":
		return instagram.Match(url)
	case "tiktok":
		return tiktok.Match(url)
	case "vkontakte":
		return vkontakte.Match(url)
	case "weibo":
		return weibo.Match(url)
	case "gravatar":
		return gravatar.Match(url)
	case "mailru":
		return mailru.Match(url)
	default:
		return false
	}
}

// FetchRecursiveWithGuess is like FetchRecursive but also guesses related profiles
// based on discovered usernames. Guessed profiles are marked with IsGuess=true
// and include confidence scores.
func FetchRecursiveWithGuess(ctx context.Context, url string, opts ...Option) ([]*profile.Profile, error) {
	// First do normal recursive fetch
	profiles, err := FetchRecursive(ctx, url, opts...)
	if err != nil {
		return nil, err
	}

	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	// Build fetcher function that wraps our Fetch
	fetcher := func(ctx context.Context, url string) (*profile.Profile, error) {
		return Fetch(ctx, url, opts...)
	}

	// Guess additional profiles
	guessCfg := guess.Config{
		Logger:           cfg.logger,
		Fetcher:          fetcher,
		PlatformDetector: PlatformForURL,
	}

	guessed := guess.Related(ctx, profiles, guessCfg)

	// Append guessed profiles to result
	profiles = append(profiles, guessed...)

	return profiles, nil
}

// GuessFromUsername guesses profiles across platforms based on a username.
// It creates a synthetic profile with the username and searches for matching
// profiles on supported platforms. All returned profiles are marked with IsGuess=true
// and include confidence scores.
func GuessFromUsername(ctx context.Context, username string, opts ...Option) ([]*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	// Create a synthetic profile with just the username
	seedProfile := &profile.Profile{
		Platform: "unknown",
		Username: username,
	}

	// Build fetcher function
	fetcher := func(ctx context.Context, url string) (*profile.Profile, error) {
		return Fetch(ctx, url, opts...)
	}

	// Guess profiles
	guessCfg := guess.Config{
		Logger:           cfg.logger,
		Fetcher:          fetcher,
		PlatformDetector: PlatformForURL,
	}

	guessed := guess.Related(ctx, []*profile.Profile{seedProfile}, guessCfg)

	return guessed, nil
}

// FetchEmailRecursive fetches profiles from email-based services and recursively
// follows social links. Multiple emails are treated as belonging to the same person,
// with results deduplicated by URL.
func FetchEmailRecursive(ctx context.Context, emails []string, opts ...Option) ([]*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	// First, get seed profiles from all emails
	seedProfiles, err := FetchEmail(ctx, emails, opts...)
	if err != nil {
		return nil, err
	}

	if len(seedProfiles) == 0 {
		return nil, nil
	}

	// Track visited URLs to avoid duplicates
	visited := make(map[string]bool)
	var allProfiles []*profile.Profile

	// Add seed profiles and mark as visited
	for _, p := range seedProfiles {
		normalizedURL := normalizeURL(p.URL)
		if !visited[normalizedURL] {
			visited[normalizedURL] = true
			allProfiles = append(allProfiles, p)
		}
	}

	// Collect all social links from seed profiles
	type queueItem struct {
		url   string
		depth int
	}
	const maxDepth = 3
	const maxLinksPerPage = 8

	var queue []queueItem
	for _, p := range seedProfiles {
		for _, link := range p.SocialLinks {
			if !visited[normalizeURL(link)] && isValidProfileURL(link) {
				queue = append(queue, queueItem{url: link, depth: 1})
			}
		}
		if p.Website != "" && !visited[normalizeURL(p.Website)] {
			queue = append(queue, queueItem{url: p.Website, depth: 1})
		}
	}

	// Process queue (same logic as FetchRecursive)
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		normalizedURL := normalizeURL(item.url)
		if visited[normalizedURL] {
			continue
		}
		visited[normalizedURL] = true

		cfg.logger.InfoContext(ctx, "fetching profile", "url", item.url, "depth", item.depth, "visited", len(visited))

		p, err := Fetch(ctx, item.url, opts...)
		if err != nil {
			cfg.logger.WarnContext(ctx, "failed to fetch profile", "url", item.url, "error", err)
			continue
		}
		allProfiles = append(allProfiles, p)

		// Don't crawl further if we've hit max depth
		if item.depth >= maxDepth {
			continue
		}

		// From generic pages, only follow known social platform links
		onlyKnownPlatforms := p.Platform == "generic"

		var linksToQueue []string
		for _, link := range p.SocialLinks {
			if !visited[normalizeURL(link)] && isValidProfileURL(link) {
				if !onlyKnownPlatforms || isSocialPlatform(link) || isSameDomainContactPage(link, item.url) {
					linksToQueue = append(linksToQueue, link)
				}
			}
		}

		if p.Website != "" && !visited[normalizeURL(p.Website)] {
			linksToQueue = append(linksToQueue, p.Website)
		}

		// Queue links from Fields map (sorted for deterministic iteration)
		keys := make([]string, 0, len(p.Fields))
		for k := range p.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := p.Fields[k]
			if isLikelySocialURL(k, v) && !visited[normalizeURL(v)] {
				linksToQueue = append(linksToQueue, v)
			}
		}

		if len(linksToQueue) > maxLinksPerPage {
			linksToQueue = linksToQueue[:maxLinksPerPage]
		}

		for _, link := range linksToQueue {
			queue = append(queue, queueItem{url: link, depth: item.depth + 1})
		}
	}

	return allProfiles, nil
}

// FetchEmail fetches profiles from email-based services (Gravatar, Mail.ru, Google, GitHub).
// It returns all profiles found for the given email addresses.
func FetchEmail(ctx context.Context, emails []string, opts ...Option) ([]*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	var profiles []*profile.Profile
	hasGitHub := false

	for _, email := range emails {
		// Always try Gravatar (works for any email)
		if p, err := fetchGravatar(ctx, email, cfg); err == nil && p != nil {
			profiles = append(profiles, p)
		}

		// Try Mail.ru for Mail.ru domain emails
		if mailru.Match(email) {
			if p, err := fetchMailRu(ctx, email, cfg); err == nil && p != nil {
				profiles = append(profiles, p)
			}
		}

		// Try Google for Gmail addresses
		if google.Match(email) {
			if p, err := fetchGoogle(ctx, email, cfg); err == nil && p != nil {
				profiles = append(profiles, p)
			}
		}

		// Try to find GitHub username from email (if we don't have a GitHub profile yet)
		if !hasGitHub {
			if p := fetchGitHubByEmail(ctx, email, cfg); p != nil {
				profiles = append(profiles, p)
				hasGitHub = true
			}
		}
	}

	return profiles, nil
}

// fetchGitHubByEmail looks up a GitHub profile by email address.
func fetchGitHubByEmail(ctx context.Context, email string, cfg *config) *profile.Profile {
	ghOpts := []github.Option{github.WithLogger(cfg.logger)}
	if cfg.cache != nil {
		ghOpts = append(ghOpts, github.WithHTTPCache(cfg.cache))
	}
	if cfg.githubToken != "" {
		ghOpts = append(ghOpts, github.WithToken(cfg.githubToken))
	}

	client, err := github.New(ctx, ghOpts...)
	if err != nil {
		cfg.logger.WarnContext(ctx, "failed to create GitHub client for email lookup", "error", err)
		return nil
	}

	username := client.UsernameFromEmail(ctx, email)
	if username == "" {
		return nil
	}

	// Fetch the full profile
	profileURL := fmt.Sprintf("https://github.com/%s", username)
	p, err := client.Fetch(ctx, profileURL)
	if err != nil {
		cfg.logger.WarnContext(ctx, "failed to fetch GitHub profile", "username", username, "error", err)
		return nil
	}

	// Add the email to the profile fields
	if p.Fields == nil {
		p.Fields = make(map[string]string)
	}
	p.Fields["lookup_email"] = email

	return p
}
