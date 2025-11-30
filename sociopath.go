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
//	import "github.com/codeGROOVE-dev/sociopath/linkedin"
//	client, _ := linkedin.New(ctx, linkedin.WithBrowserCookies())
//	profile, _ := client.Fetch(ctx, "https://linkedin.com/in/johndoe")
package sociopath

import (
	"context"
	"log/slog"
	"strings"

	"github.com/codeGROOVE-dev/sociopath/bilibili"
	"github.com/codeGROOVE-dev/sociopath/bluesky"
	"github.com/codeGROOVE-dev/sociopath/cache"
	"github.com/codeGROOVE-dev/sociopath/devto"
	"github.com/codeGROOVE-dev/sociopath/generic"
	"github.com/codeGROOVE-dev/sociopath/github"
	"github.com/codeGROOVE-dev/sociopath/guess"
	"github.com/codeGROOVE-dev/sociopath/habr"
	"github.com/codeGROOVE-dev/sociopath/instagram"
	"github.com/codeGROOVE-dev/sociopath/linkedin"
	"github.com/codeGROOVE-dev/sociopath/linktree"
	"github.com/codeGROOVE-dev/sociopath/mastodon"
	"github.com/codeGROOVE-dev/sociopath/medium"
	"github.com/codeGROOVE-dev/sociopath/profile"
	"github.com/codeGROOVE-dev/sociopath/reddit"
	"github.com/codeGROOVE-dev/sociopath/stackoverflow"
	"github.com/codeGROOVE-dev/sociopath/substack"
	"github.com/codeGROOVE-dev/sociopath/tiktok"
	"github.com/codeGROOVE-dev/sociopath/twitter"
	"github.com/codeGROOVE-dev/sociopath/vkontakte"
	"github.com/codeGROOVE-dev/sociopath/weibo"
	"github.com/codeGROOVE-dev/sociopath/youtube"
	"github.com/codeGROOVE-dev/sociopath/zhihu"
)

type (
	// Profile re-exports profile.Profile for convenience.
	Profile = profile.Profile
	// HTTPCache re-exports cache.HTTPCache for convenience.
	HTTPCache = cache.HTTPCache
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

type config struct {
	cookies        map[string]string
	cache          cache.HTTPCache
	logger         *slog.Logger
	browserCookies bool
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
func WithHTTPCache(httpCache cache.HTTPCache) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// Fetch retrieves a profile from the given URL.
// The platform is automatically detected from the URL.
func Fetch(ctx context.Context, url string, opts ...Option) (*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	// Try each platform's Match function in order of specificity
	// Note: Order matters! More specific patterns should come before generic ones.
	// TikTok must come before Mastodon because Mastodon matches /@username pattern.
	// Substack must come before generic because it has specific domain pattern.
	switch {
	case linkedin.Match(url):
		return fetchLinkedIn(ctx, url, cfg)
	case twitter.Match(url):
		return fetchTwitter(ctx, url, cfg)
	case linktree.Match(url):
		return fetchLinktree(ctx, url, cfg)
	case github.Match(url):
		return fetchGitHub(ctx, url, cfg)
	case medium.Match(url):
		return fetchMedium(ctx, url, cfg)
	case reddit.Match(url):
		return fetchReddit(ctx, url, cfg)
	case youtube.Match(url):
		return fetchYouTube(ctx, url, cfg)
	case substack.Match(url):
		return fetchSubstack(ctx, url, cfg)
	case weibo.Match(url):
		return fetchWeibo(ctx, url, cfg)
	case zhihu.Match(url):
		return fetchZhihu(ctx, url, cfg)
	case bilibili.Match(url):
		return fetchBilibili(ctx, url, cfg)
	case bluesky.Match(url):
		return fetchBlueSky(ctx, url, cfg)
	case devto.Match(url):
		return fetchDevTo(ctx, url, cfg)
	case stackoverflow.Match(url):
		return fetchStackOverflow(ctx, url, cfg)
	case habr.Match(url):
		return fetchHabr(ctx, url, cfg)
	case instagram.Match(url):
		return fetchInstagram(ctx, url, cfg)
	case tiktok.Match(url):
		return fetchTikTok(ctx, url, cfg)
	case vkontakte.Match(url):
		return fetchVKontakte(ctx, url, cfg)
	case mastodon.Match(url):
		return fetchMastodon(ctx, url, cfg)
	default:
		return fetchGeneric(ctx, url, cfg)
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

	client, err := vkontakte.New(ctx, opts...)
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

	client, err := github.New(ctx, opts...)
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

func fetchWeibo(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []weibo.Option
	if len(cfg.cookies) > 0 {
		opts = append(opts, weibo.WithCookies(cfg.cookies))
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

func fetchZhihu(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []zhihu.Option
	if cfg.cache != nil {
		opts = append(opts, zhihu.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, zhihu.WithLogger(cfg.logger))
	}

	client, err := zhihu.New(ctx, opts...)
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
func FetchRecursive(ctx context.Context, url string, opts ...Option) ([]*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	visited := make(map[string]bool)
	var profiles []*profile.Profile

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

		// Queue links from Fields map
		for key, value := range p.Fields {
			if isLikelySocialURL(key, value) && !visited[normalizeURL(value)] {
				linksToQueue = append(linksToQueue, value)
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
		medium.Match(url) ||
		reddit.Match(url) ||
		youtube.Match(url) ||
		substack.Match(url) ||
		weibo.Match(url) ||
		zhihu.Match(url) ||
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
		Logger:  cfg.logger,
		Fetcher: fetcher,
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
		Logger:  cfg.logger,
		Fetcher: fetcher,
	}

	guessed := guess.Related(ctx, []*profile.Profile{seedProfile}, guessCfg)

	return guessed, nil
}
