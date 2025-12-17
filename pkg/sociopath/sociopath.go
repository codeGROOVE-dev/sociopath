// Package sociopath provides a unified API for fetching social media profiles.
//
// Basic usage:
//
//	profile, err := sociopath.Fetch(ctx, "https://mastodon.social/@johndoe")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(profile.DisplayName, profile.Bio)
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
	"maps"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/arstechnica"
	"github.com/codeGROOVE-dev/sociopath/pkg/avatar"
	"github.com/codeGROOVE-dev/sociopath/pkg/bilibili"
	"github.com/codeGROOVE-dev/sociopath/pkg/blogger"
	"github.com/codeGROOVE-dev/sociopath/pkg/bluesky"
	"github.com/codeGROOVE-dev/sociopath/pkg/boardgamegeek"
	"github.com/codeGROOVE-dev/sociopath/pkg/bugcrowd"
	"github.com/codeGROOVE-dev/sociopath/pkg/calcom"
	"github.com/codeGROOVE-dev/sociopath/pkg/calendly"
	"github.com/codeGROOVE-dev/sociopath/pkg/codeberg"
	"github.com/codeGROOVE-dev/sociopath/pkg/codewars"
	"github.com/codeGROOVE-dev/sociopath/pkg/crates"
	"github.com/codeGROOVE-dev/sociopath/pkg/csdn"
	"github.com/codeGROOVE-dev/sociopath/pkg/devto"
	"github.com/codeGROOVE-dev/sociopath/pkg/disqus"
	"github.com/codeGROOVE-dev/sociopath/pkg/dockerhub"
	"github.com/codeGROOVE-dev/sociopath/pkg/douban"
	"github.com/codeGROOVE-dev/sociopath/pkg/duolingo"
	"github.com/codeGROOVE-dev/sociopath/pkg/generic"
	"github.com/codeGROOVE-dev/sociopath/pkg/gitee"
	"github.com/codeGROOVE-dev/sociopath/pkg/github"
	"github.com/codeGROOVE-dev/sociopath/pkg/gitlab"
	"github.com/codeGROOVE-dev/sociopath/pkg/goodreads"
	"github.com/codeGROOVE-dev/sociopath/pkg/google"
	"github.com/codeGROOVE-dev/sociopath/pkg/googlecal"
	"github.com/codeGROOVE-dev/sociopath/pkg/gravatar"
	"github.com/codeGROOVE-dev/sociopath/pkg/guess"
	"github.com/codeGROOVE-dev/sociopath/pkg/habr"
	"github.com/codeGROOVE-dev/sociopath/pkg/hackernews"
	"github.com/codeGROOVE-dev/sociopath/pkg/hackerone"
	"github.com/codeGROOVE-dev/sociopath/pkg/hackerrank"
	"github.com/codeGROOVE-dev/sociopath/pkg/hashnode"
	"github.com/codeGROOVE-dev/sociopath/pkg/hexpm"
	"github.com/codeGROOVE-dev/sociopath/pkg/holopin"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/huggingface"
	"github.com/codeGROOVE-dev/sociopath/pkg/instagram"
	"github.com/codeGROOVE-dev/sociopath/pkg/intensedebate"
	"github.com/codeGROOVE-dev/sociopath/pkg/juejin"
	"github.com/codeGROOVE-dev/sociopath/pkg/keybase"
	"github.com/codeGROOVE-dev/sociopath/pkg/launchpad"
	"github.com/codeGROOVE-dev/sociopath/pkg/leetcode"
	"github.com/codeGROOVE-dev/sociopath/pkg/linkedin"
	"github.com/codeGROOVE-dev/sociopath/pkg/linktree"
	"github.com/codeGROOVE-dev/sociopath/pkg/lobsters"
	"github.com/codeGROOVE-dev/sociopath/pkg/mailru"
	"github.com/codeGROOVE-dev/sociopath/pkg/mastodon"
	"github.com/codeGROOVE-dev/sociopath/pkg/medium"
	"github.com/codeGROOVE-dev/sociopath/pkg/microblog"
	"github.com/codeGROOVE-dev/sociopath/pkg/observablehq"
	"github.com/codeGROOVE-dev/sociopath/pkg/orcid"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
	"github.com/codeGROOVE-dev/sociopath/pkg/pypi"
	"github.com/codeGROOVE-dev/sociopath/pkg/qiita"
	"github.com/codeGROOVE-dev/sociopath/pkg/reddit"
	"github.com/codeGROOVE-dev/sociopath/pkg/replit"
	"github.com/codeGROOVE-dev/sociopath/pkg/rubygems"
	"github.com/codeGROOVE-dev/sociopath/pkg/scratch"
	"github.com/codeGROOVE-dev/sociopath/pkg/sessionize"
	"github.com/codeGROOVE-dev/sociopath/pkg/slashdot"
	"github.com/codeGROOVE-dev/sociopath/pkg/slideshare"
	"github.com/codeGROOVE-dev/sociopath/pkg/stackoverflow"
	"github.com/codeGROOVE-dev/sociopath/pkg/steam"
	"github.com/codeGROOVE-dev/sociopath/pkg/strava"
	"github.com/codeGROOVE-dev/sociopath/pkg/substack"
	"github.com/codeGROOVE-dev/sociopath/pkg/telegram"
	"github.com/codeGROOVE-dev/sociopath/pkg/tiktok"
	"github.com/codeGROOVE-dev/sociopath/pkg/tradingview"
	"github.com/codeGROOVE-dev/sociopath/pkg/tryhackme"
	"github.com/codeGROOVE-dev/sociopath/pkg/tumblr"
	"github.com/codeGROOVE-dev/sociopath/pkg/twitch"
	"github.com/codeGROOVE-dev/sociopath/pkg/twitter"
	"github.com/codeGROOVE-dev/sociopath/pkg/v2ex"
	"github.com/codeGROOVE-dev/sociopath/pkg/velog"
	"github.com/codeGROOVE-dev/sociopath/pkg/vkontakte"
	"github.com/codeGROOVE-dev/sociopath/pkg/weibo"
	"github.com/codeGROOVE-dev/sociopath/pkg/youtube"
	"github.com/codeGROOVE-dev/sociopath/pkg/zenn"
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
	cache                    httpcache.Cacher
	cookies                  map[string]string
	logger                   *slog.Logger
	githubToken              string
	browserCookies           bool
	emailHints               []string // Email addresses to associate with profiles
	maxCandidatesPerPlatform int      // Limit guess candidates per platform (default: 2)
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
func WithHTTPCache(cache httpcache.Cacher) Option {
	return func(c *config) { c.cache = cache }
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

// WithMaxCandidatesPerPlatform limits how many guess candidates are tried per platform.
// This controls the number of URLs probed when guessing profiles on platforms
// like Mastodon (multiple servers) or when trying multiple username variations.
// Default is 2. Set to 0 to use the default.
func WithMaxCandidatesPerPlatform(n int) Option {
	return func(c *config) { c.maxCandidatesPerPlatform = n }
}

// Fetch retrieves a profile from the given URL.
// The platform is automatically detected from the URL.
//
//nolint:maintidx,revive // complexity is inherent to supporting 60+ platforms
func Fetch(ctx context.Context, url string, opts ...Option) (*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	var p *profile.Profile //nolint:varnamelen // short name is clear in this switch context
	var err error
	var platform string

	start := time.Now()

	// Try each platform's Match function in order of specificity
	// Note: Order matters! More specific patterns should come before generic ones.
	// TikTok must come before Mastodon because Mastodon matches /@username pattern.
	// Substack must come before generic because it has specific domain pattern.
	switch {
	case linkedin.Match(url):
		platform = "linkedin"
		p, err = fetchLinkedIn(ctx, url, cfg)
	case twitter.Match(url):
		platform = "twitter"
		p, err = fetchTwitter(ctx, url, cfg)
	case linktree.Match(url):
		platform = "linktree"
		p, err = fetchLinktree(ctx, url, cfg)
	case github.Match(url):
		platform = "github"
		p, err = fetchGitHub(ctx, url, cfg)
	case medium.Match(url):
		platform = "medium"
		p, err = fetchMedium(ctx, url, cfg)
	case microblog.Match(url):
		platform = "microblog"
		p, err = fetchMicroblog(ctx, url, cfg)
	case reddit.Match(url):
		platform = "reddit"
		p, err = fetchReddit(ctx, url, cfg)
	case replit.Match(url):
		platform = "replit"
		p, err = fetchReplit(ctx, url, cfg)
	case youtube.Match(url):
		platform = "youtube"
		p, err = fetchYouTube(ctx, url, cfg)
	case substack.Match(url):
		platform = "substack"
		p, err = fetchSubstack(ctx, url, cfg)
	case bilibili.Match(url):
		platform = "bilibili"
		p, err = fetchBilibili(ctx, url, cfg)
	case codeberg.Match(url):
		platform = "codeberg"
		p, err = fetchCodeberg(ctx, url, cfg)
	case codewars.Match(url):
		platform = "codewars"
		p, err = fetchCodewars(ctx, url, cfg)
	case bluesky.Match(url):
		platform = "bluesky"
		p, err = fetchBlueSky(ctx, url, cfg)
	case devto.Match(url):
		platform = "devto"
		p, err = fetchDevTo(ctx, url, cfg)
	case stackoverflow.Match(url):
		platform = "stackoverflow"
		p, err = fetchStackOverflow(ctx, url, cfg)
	case habr.Match(url):
		platform = "habr"
		p, err = fetchHabr(ctx, url, cfg)
	case instagram.Match(url):
		platform = "instagram"
		p, err = fetchInstagram(ctx, url, cfg)
	case keybase.Match(url):
		platform = "keybase"
		p, err = fetchKeybase(ctx, url, cfg)
	case launchpad.Match(url):
		platform = "launchpad"
		p, err = fetchLaunchpad(ctx, url, cfg)
	case crates.Match(url):
		platform = "crates"
		p, err = fetchCrates(ctx, url, cfg)
	case disqus.Match(url):
		platform = "disqus"
		p, err = fetchDisqus(ctx, url, cfg)
	case intensedebate.Match(url):
		platform = "intensedebate"
		p, err = fetchIntenseDebate(ctx, url, cfg)
	case dockerhub.Match(url):
		platform = "dockerhub"
		p, err = fetchDockerHub(ctx, url, cfg)
	case gitlab.Match(url):
		platform = "gitlab"
		p, err = fetchGitLab(ctx, url, cfg)
	case tiktok.Match(url):
		platform = "tiktok"
		p, err = fetchTikTok(ctx, url, cfg)
	case vkontakte.Match(url):
		platform = "vkontakte"
		p, err = fetchVKontakte(ctx, url, cfg)
	case weibo.Match(url):
		platform = "weibo"
		p, err = fetchWeibo(ctx, url, cfg)
	case mailru.Match(url):
		platform = "mailru"
		p, err = fetchMailRu(ctx, url, cfg)
	case google.Match(url):
		platform = "google"
		p, err = fetchGoogle(ctx, url, cfg)
	case googlecal.Match(url):
		platform = "googlecal"
		p, err = fetchGoogleCal(ctx, url, cfg)
	case gravatar.Match(url):
		platform = "gravatar"
		p, err = fetchGravatar(ctx, url, cfg)
	case hackernews.Match(url):
		platform = "hackernews"
		p, err = fetchHackerNews(ctx, url, cfg)
	case hackerone.Match(url):
		platform = "hackerone"
		p, err = fetchHackerOne(ctx, url, cfg)
	case bugcrowd.Match(url):
		platform = "bugcrowd"
		p, err = fetchBugcrowd(ctx, url, cfg)
	case calcom.Match(url):
		platform = "calcom"
		p, err = fetchCalcom(ctx, url, cfg)
	case calendly.Match(url):
		platform = "calendly"
		p, err = fetchCalendly(ctx, url, cfg)
	case lobsters.Match(url):
		platform = "lobsters"
		p, err = fetchLobsters(ctx, url, cfg)
	case arstechnica.Match(url):
		platform = "arstechnica"
		p, err = fetchArsTechnica(ctx, url, cfg)
	case sessionize.Match(url):
		platform = "sessionize"
		p, err = fetchSessionize(ctx, url, cfg)
	case slideshare.Match(url):
		platform = "slideshare"
		p, err = fetchSlideshare(ctx, url, cfg)
	case strava.Match(url):
		platform = "strava"
		p, err = fetchStrava(ctx, url, cfg)
	case slashdot.Match(url):
		platform = "slashdot"
		p, err = fetchSlashdot(ctx, url, cfg)
	case tumblr.Match(url):
		platform = "tumblr"
		p, err = fetchTumblr(ctx, url, cfg)
	case observablehq.Match(url):
		platform = "observablehq"
		p, err = fetchObservableHQ(ctx, url, cfg)
	case blogger.Match(url):
		platform = "blogger"
		p, err = fetchBlogger(ctx, url, cfg)
	case boardgamegeek.Match(url):
		platform = "boardgamegeek"
		p, err = fetchBoardGameGeek(ctx, url, cfg)
	case duolingo.Match(url):
		platform = "duolingo"
		p, err = fetchDuolingo(ctx, url, cfg)
	case hackerrank.Match(url):
		platform = "hackerrank"
		p, err = fetchHackerRank(ctx, url, cfg)
	case tradingview.Match(url):
		platform = "tradingview"
		p, err = fetchTradingView(ctx, url, cfg)
	case douban.Match(url):
		platform = "douban"
		p, err = fetchDouban(ctx, url, cfg)
	case juejin.Match(url):
		platform = "juejin"
		p, err = fetchJuejin(ctx, url, cfg)
	case csdn.Match(url):
		platform = "csdn"
		p, err = fetchCSDN(ctx, url, cfg)
	case v2ex.Match(url):
		platform = "v2ex"
		p, err = fetchV2EX(ctx, url, cfg)
	case gitee.Match(url):
		platform = "gitee"
		p, err = fetchGitee(ctx, url, cfg)
	case velog.Match(url):
		platform = "velog"
		p, err = fetchVelog(ctx, url, cfg)
	case qiita.Match(url):
		platform = "qiita"
		p, err = fetchQiita(ctx, url, cfg)
	case zenn.Match(url):
		platform = "zenn"
		p, err = fetchZenn(ctx, url, cfg)
	case hashnode.Match(url):
		platform = "hashnode"
		p, err = fetchHashnode(ctx, url, cfg)
	case orcid.Match(url):
		platform = "orcid"
		p, err = fetchORCID(ctx, url, cfg)
	case hexpm.Match(url):
		platform = "hexpm"
		p, err = fetchHexpm(ctx, url, cfg)
	case telegram.Match(url):
		platform = "telegram"
		p, err = fetchTelegram(ctx, url, cfg)
	case tryhackme.Match(url):
		platform = "tryhackme"
		p, err = fetchTryHackMe(ctx, url, cfg)
	case twitch.Match(url):
		platform = "twitch"
		p, err = fetchTwitch(ctx, url, cfg)
	case steam.Match(url):
		platform = "steam"
		p, err = fetchSteam(ctx, url, cfg)
	case leetcode.Match(url):
		platform = "leetcode"
		p, err = fetchLeetCode(ctx, url, cfg)
	case goodreads.Match(url):
		platform = "goodreads"
		p, err = fetchGoodreads(ctx, url, cfg)
	case rubygems.Match(url):
		platform = "rubygems"
		p, err = fetchRubyGems(ctx, url, cfg)
	case huggingface.Match(url):
		platform = "huggingface"
		p, err = fetchHuggingFace(ctx, url, cfg)
	case holopin.Match(url):
		platform = "holopin"
		p, err = fetchHolopin(ctx, url, cfg)
	case mastodon.Match(url):
		platform = "mastodon"
		p, err = fetchMastodon(ctx, url, cfg)
	case pypi.Match(url):
		platform = "pypi"
		p, err = fetchPyPI(ctx, url, cfg)
	case scratch.Match(url):
		platform = "scratch"
		p, err = fetchScratch(ctx, url, cfg)
	default:
		platform = "generic"
		p, err = fetchGeneric(ctx, url, cfg)
	}

	// Log fetch latency
	if cfg.logger != nil {
		latency := time.Since(start).Milliseconds()
		cfg.logger.DebugContext(ctx, "fetch completed",
			"platform", platform, "url", url, "latency_ms", latency, "error", err != nil)
	}

	// Apply email hints to the profile
	if err == nil && p != nil && len(cfg.emailHints) > 0 {
		applyEmailHints(p, cfg.emailHints)
	}

	// Compute avatar hash for cross-platform matching
	if err == nil && p != nil && p.AvatarURL != "" {
		p.AvatarHash = avatar.Hash(ctx, cfg.cache, p.AvatarURL, cfg.logger)
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

	// Configure Brave Search if API key is available.
	if apiKey := linkedin.LoadBraveAPIKey(); apiKey != "" {
		var braveOpts []linkedin.BraveOption
		if cfg.cache != nil {
			braveOpts = append(braveOpts, linkedin.WithBraveCache(cfg.cache))
		}
		if cfg.logger != nil {
			braveOpts = append(braveOpts, linkedin.WithBraveLogger(cfg.logger))
		}
		opts = append(opts, linkedin.WithSearcher(linkedin.NewBraveSearcher(apiKey, braveOpts...)))
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
	if cfg.cache != nil {
		opts = append(opts, instagram.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, instagram.WithLogger(cfg.logger))
	}

	client, err := instagram.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchKeybase(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []keybase.Option
	if cfg.cache != nil {
		opts = append(opts, keybase.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, keybase.WithLogger(cfg.logger))
	}

	client, err := keybase.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchLaunchpad(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []launchpad.Option
	if cfg.cache != nil {
		opts = append(opts, launchpad.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, launchpad.WithLogger(cfg.logger))
	}

	client, err := launchpad.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchCrates(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []crates.Option
	if cfg.cache != nil {
		opts = append(opts, crates.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, crates.WithLogger(cfg.logger))
	}

	client, err := crates.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchDisqus(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []disqus.Option
	if cfg.cache != nil {
		opts = append(opts, disqus.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, disqus.WithLogger(cfg.logger))
	}

	client, err := disqus.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchIntenseDebate(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []intensedebate.Option
	if cfg.cache != nil {
		opts = append(opts, intensedebate.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, intensedebate.WithLogger(cfg.logger))
	}

	client, err := intensedebate.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchDockerHub(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []dockerhub.Option
	if cfg.cache != nil {
		opts = append(opts, dockerhub.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, dockerhub.WithLogger(cfg.logger))
	}

	client, err := dockerhub.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchGitLab(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []gitlab.Option
	if cfg.cache != nil {
		opts = append(opts, gitlab.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, gitlab.WithLogger(cfg.logger))
	}

	client, err := gitlab.New(ctx, opts...)
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

func fetchGoogleCal(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []googlecal.Option
	if cfg.cache != nil {
		opts = append(opts, googlecal.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, googlecal.WithLogger(cfg.logger))
	}

	client, err := googlecal.New(ctx, opts...)
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

func fetchMicroblog(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []microblog.Option
	if cfg.cache != nil {
		opts = append(opts, microblog.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, microblog.WithLogger(cfg.logger))
	}

	client, err := microblog.New(ctx, opts...)
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

func fetchReplit(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []replit.Option
	if cfg.cache != nil {
		opts = append(opts, replit.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, replit.WithLogger(cfg.logger))
	}

	client, err := replit.New(ctx, opts...)
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

func fetchCodewars(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []codewars.Option
	if cfg.cache != nil {
		opts = append(opts, codewars.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, codewars.WithLogger(cfg.logger))
	}

	client, err := codewars.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHackerNews(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []hackernews.Option
	if cfg.cache != nil {
		opts = append(opts, hackernews.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, hackernews.WithLogger(cfg.logger))
	}

	client, err := hackernews.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHackerOne(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []hackerone.Option
	if cfg.cache != nil {
		opts = append(opts, hackerone.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, hackerone.WithLogger(cfg.logger))
	}

	client, err := hackerone.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchBugcrowd(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []bugcrowd.Option
	if cfg.cache != nil {
		opts = append(opts, bugcrowd.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, bugcrowd.WithLogger(cfg.logger))
	}

	client, err := bugcrowd.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchCalcom(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []calcom.Option
	if cfg.cache != nil {
		opts = append(opts, calcom.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, calcom.WithLogger(cfg.logger))
	}

	client, err := calcom.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchCalendly(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []calendly.Option
	if cfg.cache != nil {
		opts = append(opts, calendly.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, calendly.WithLogger(cfg.logger))
	}

	client, err := calendly.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchLobsters(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []lobsters.Option
	if cfg.cache != nil {
		opts = append(opts, lobsters.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, lobsters.WithLogger(cfg.logger))
	}

	client, err := lobsters.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchArsTechnica(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []arstechnica.Option
	if cfg.cache != nil {
		opts = append(opts, arstechnica.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, arstechnica.WithLogger(cfg.logger))
	}

	client, err := arstechnica.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchSessionize(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []sessionize.Option
	if cfg.cache != nil {
		opts = append(opts, sessionize.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, sessionize.WithLogger(cfg.logger))
	}

	client, err := sessionize.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchSlideshare(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []slideshare.Option
	if cfg.cache != nil {
		opts = append(opts, slideshare.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, slideshare.WithLogger(cfg.logger))
	}

	client, err := slideshare.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchStrava(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []strava.Option
	if cfg.cache != nil {
		opts = append(opts, strava.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, strava.WithLogger(cfg.logger))
	}

	client, err := strava.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchDouban(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []douban.Option
	if cfg.cache != nil {
		opts = append(opts, douban.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, douban.WithLogger(cfg.logger))
	}

	client, err := douban.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchJuejin(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []juejin.Option
	if cfg.cache != nil {
		opts = append(opts, juejin.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, juejin.WithLogger(cfg.logger))
	}

	client, err := juejin.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchCSDN(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []csdn.Option
	if cfg.cache != nil {
		opts = append(opts, csdn.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, csdn.WithLogger(cfg.logger))
	}

	client, err := csdn.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchV2EX(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []v2ex.Option
	if cfg.cache != nil {
		opts = append(opts, v2ex.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, v2ex.WithLogger(cfg.logger))
	}

	client, err := v2ex.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchGitee(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []gitee.Option
	if cfg.cache != nil {
		opts = append(opts, gitee.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, gitee.WithLogger(cfg.logger))
	}

	client, err := gitee.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchVelog(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []velog.Option
	if cfg.cache != nil {
		opts = append(opts, velog.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, velog.WithLogger(cfg.logger))
	}

	client, err := velog.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchQiita(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []qiita.Option
	if cfg.cache != nil {
		opts = append(opts, qiita.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, qiita.WithLogger(cfg.logger))
	}

	client, err := qiita.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchZenn(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []zenn.Option
	if cfg.cache != nil {
		opts = append(opts, zenn.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, zenn.WithLogger(cfg.logger))
	}

	client, err := zenn.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHashnode(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []hashnode.Option
	if cfg.cache != nil {
		opts = append(opts, hashnode.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, hashnode.WithLogger(cfg.logger))
	}

	client, err := hashnode.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchORCID(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []orcid.Option
	if cfg.cache != nil {
		opts = append(opts, orcid.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, orcid.WithLogger(cfg.logger))
	}

	client, err := orcid.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHexpm(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []hexpm.Option
	if cfg.cache != nil {
		opts = append(opts, hexpm.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, hexpm.WithLogger(cfg.logger))
	}

	client, err := hexpm.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchTelegram(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []telegram.Option
	if cfg.cache != nil {
		opts = append(opts, telegram.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, telegram.WithLogger(cfg.logger))
	}

	client, err := telegram.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchTryHackMe(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []tryhackme.Option
	if cfg.cache != nil {
		opts = append(opts, tryhackme.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, tryhackme.WithLogger(cfg.logger))
	}

	client, err := tryhackme.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchTwitch(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []twitch.Option
	if cfg.cache != nil {
		opts = append(opts, twitch.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, twitch.WithLogger(cfg.logger))
	}

	client, err := twitch.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchSteam(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []steam.Option
	if cfg.cache != nil {
		opts = append(opts, steam.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, steam.WithLogger(cfg.logger))
	}

	client, err := steam.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchLeetCode(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []leetcode.Option
	if cfg.cache != nil {
		opts = append(opts, leetcode.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, leetcode.WithLogger(cfg.logger))
	}

	client, err := leetcode.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchGoodreads(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []goodreads.Option
	if cfg.cache != nil {
		opts = append(opts, goodreads.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, goodreads.WithLogger(cfg.logger))
	}

	client, err := goodreads.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchRubyGems(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []rubygems.Option
	if cfg.cache != nil {
		opts = append(opts, rubygems.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, rubygems.WithLogger(cfg.logger))
	}

	client, err := rubygems.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHuggingFace(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []huggingface.Option
	if cfg.cache != nil {
		opts = append(opts, huggingface.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, huggingface.WithLogger(cfg.logger))
	}

	client, err := huggingface.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHolopin(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []holopin.Option
	if cfg.cache != nil {
		opts = append(opts, holopin.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, holopin.WithLogger(cfg.logger))
	}

	client, err := holopin.New(ctx, opts...)
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
// It deduplicates by URL and skips same-platform links for single-account platforms.
// URLs at each depth level are fetched in parallel for better performance.
//
//nolint:gocognit,varnamelen,maintidx // recursive crawling with multi-platform auth fallback is inherently complex
func FetchRecursive(ctx context.Context, url string, opts ...Option) ([]*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	var mu sync.Mutex
	visited := make(map[string]bool)
	collectedPlatforms := make(map[string]bool) // Track platforms we've already got profiles for
	var out []*profile.Profile
	initial := ""

	const maxDepth, maxLinks = 3, 8

	// Process URLs level by level, fetching all URLs at each depth in parallel
	currentLevel := []string{url}

	for depth := 0; depth <= maxDepth && len(currentLevel) > 0; depth++ {
		cfg.logger.DebugContext(ctx, "processing depth level", "depth", depth, "urls", len(currentLevel))

		// Results from this level's parallel fetches
		type fetchResult struct {
			profile  *profile.Profile
			newLinks []string
		}
		results := make(chan fetchResult, len(currentLevel))

		var wg sync.WaitGroup
		for _, urlStr := range currentLevel {
			// Check visited before spawning goroutine
			mu.Lock()
			norm := normalizeURL(urlStr)
			if visited[norm] {
				mu.Unlock()
				continue
			}
			visited[norm] = true
			mu.Unlock()

			wg.Add(1) //nolint:revive // errgroup not needed for this simple use case
			go func(urlStr string, depth int) {
				defer wg.Done()

				// Handle redirects, preserving usernames that might be lost
				p, resolved := handleRedirectWithUsernamePreservation(ctx, urlStr, cfg.cache, cfg.logger)
				if p != nil {
					results <- fetchResult{profile: p}
					return
				}

				// If redirect resolved to a different URL, check if it's already visited
				if resolved != urlStr {
					mu.Lock()
					norm := normalizeURL(resolved)
					alreadyVisited := visited[norm]
					if !alreadyVisited {
						visited[norm] = true
					}
					mu.Unlock()
					if alreadyVisited {
						return
					}
					urlStr = resolved
				}

				cfg.logger.InfoContext(ctx, "fetching profile", "url", urlStr, "depth", depth)

				p, err := Fetch(ctx, urlStr, opts...)
				if err != nil {
					// For auth-required platforms (except LinkedIn), try generic parser
					authPlatform := twitter.Match(urlStr) || instagram.Match(urlStr) ||
						tiktok.Match(urlStr) || vkontakte.Match(urlStr)
					if !authPlatform || linkedin.Match(urlStr) {
						cfg.logger.WarnContext(ctx, "failed to fetch profile", "url", urlStr, "error", err)
						if errors.Is(err, profile.ErrNoCookies) || errors.Is(err, profile.ErrAuthRequired) {
							results <- fetchResult{profile: &profile.Profile{
								Platform: PlatformForURL(urlStr),
								URL:      urlStr,
								Error:    "login required",
							}}
						}
						return
					}
					cfg.logger.InfoContext(ctx, "fetch failed, trying generic", "url", urlStr, "error", err)
					if p, err = fetchGeneric(ctx, urlStr, cfg); err != nil {
						cfg.logger.WarnContext(ctx, "generic fetch failed", "url", urlStr, "error", err)
						return
					}
					if actualPlatform := PlatformForURL(urlStr); actualPlatform != "website" {
						p.Platform = actualPlatform
						p.Content = ""
					}
				}

				// Collect new links for next level (only if not at max depth)
				var newLinks []string
				if depth < maxDepth {
					onlyKnown := p.Platform == "website"

					mu.Lock()
					initialPlatform := initial
					platforms := make(map[string]bool, len(collectedPlatforms))
					maps.Copy(platforms, collectedPlatforms)
					mu.Unlock()

					for _, link := range p.SocialLinks {
						if !isValidProfileURL(link) {
							continue
						}
						linkPlatform := PlatformForURL(link)
						if platforms[linkPlatform] {
							continue
						}
						if isSingleAccountPlatform(initialPlatform) && platformMatches(link, initialPlatform) {
							continue
						}
						if !onlyKnown || isSocialPlatform(link) || isSameDomainContactPage(link, urlStr) {
							newLinks = append(newLinks, link)
						}
					}
					if p.Website != "" && isValidProfileURL(p.Website) {
						newLinks = append(newLinks, p.Website)
					}

					// Check Fields for social URLs
					keys := make([]string, 0, len(p.Fields))
					for k := range p.Fields {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						if v := p.Fields[k]; isLikelySocialURL(k, v) && isValidProfileURL(v) {
							newLinks = append(newLinks, v)
						}
					}

					if len(newLinks) > maxLinks {
						newLinks = newLinks[:maxLinks]
					}
				}

				results <- fetchResult{profile: p, newLinks: newLinks}
			}(urlStr, depth)
		}

		// Close results channel when all goroutines complete
		go func() {
			wg.Wait()
			close(results)
		}()

		// Collect results and build next level
		var nextLevel []string
		for result := range results {
			if result.profile != nil {
				out = append(out, result.profile)

				// Track platforms and initial
				if depth == 0 && initial == "" {
					initial = result.profile.Platform
				}
				if isSingleAccountPlatform(result.profile.Platform) && depth <= 1 {
					mu.Lock()
					collectedPlatforms[result.profile.Platform] = true
					mu.Unlock()
				}
			}

			// Add new links for next level (deduped against visited)
			for _, link := range result.newLinks {
				mu.Lock()
				norm := normalizeURL(link)
				if !visited[norm] && !collectedPlatforms[PlatformForURL(link)] {
					nextLevel = append(nextLevel, link)
				}
				mu.Unlock()
			}
		}

		// Dedupe next level
		currentLevel = dedupeLinks(nextLevel, visited)
	}

	return out, nil
}

// isValidProfileURL filters out non-profile URLs (e.g. twitter.com/home).
func isValidProfileURL(url string) bool {
	// Filter out official platform accounts that aren't user profiles
	if isOfficialPlatformAccount(url) {
		return false
	}
	if twitter.Match(url) {
		return twitter.IsValidProfileURL(url)
	}
	// Filter out known blog/content domains that don't have user profiles
	if isKnownBlogDomain(url) {
		return false
	}
	// Filter out content aggregation URLs (tag pages, category pages, etc.)
	if isContentAggregationURL(url) {
		return false
	}
	return true
}

// isKnownBlogDomain returns true if the URL is from a known blog/content domain
// that doesn't have user profiles we should crawl.
func isKnownBlogDomain(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	blogDomains := []string{
		"github.blog", "blog.github.com",
		"engineering.fb.com", "engineering.linkedin.com",
		"netflixtechblog.com", "uber.com/blog", "airbnb.io",
		"aws.amazon.com/blogs", "cloud.google.com/blog",
		"devblogs.microsoft.com", "techcommunity.microsoft.com",
	}
	for _, domain := range blogDomains {
		if strings.Contains(lower, domain) {
			return true
		}
	}
	return false
}

// isContentAggregationURL returns true if the URL is a content aggregation page
// (tag, category, archive, wiki) rather than a user profile.
func isContentAggregationURL(urlStr string) bool {
	lower := strings.ToLower(urlStr)

	// Wiki domains - always filter
	if strings.Contains(lower, "-wiki.") || strings.Contains(lower, "wiki.") ||
		strings.Contains(lower, "wikipedia.org") {
		return true
	}

	// Content aggregation path patterns - always filter
	patterns := []string{
		"/tag/", "/tags/",
		"/category/", "/categories/",
		"/archive/", "/archives/",
		"/topic/", "/topics/",
		"/label/", "/labels/",
		"/wiki/", // wiki pages
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}

	// Corporate/platform path patterns - only for known large domains
	if isKnownCorporateDomain(lower) {
		corpPatterns := []string{
			"/features", "/pricing", "/enterprise",
			"/customer-stories", "/customers",
			"/blog/", "/press/", "/news/",
		}
		for _, p := range corpPatterns {
			if strings.Contains(lower, p) {
				return true
			}
		}
	}

	return false
}

// isKnownCorporateDomain returns true if the URL is from a known corporate/platform domain.
func isKnownCorporateDomain(lower string) bool {
	domains := []string{
		"github.com", "gitlab.com", "bitbucket.org",
		"twitter.com", "x.com", "facebook.com", "instagram.com",
		"linkedin.com", "youtube.com", "tiktok.com",
		"microsoft.com", "google.com", "amazon.com", "apple.com",
		"netflix.com", "uber.com", "airbnb.com",
	}
	for _, d := range domains {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

// isOfficialPlatformAccount returns true if the URL points to an official platform account
// rather than a user profile. These accounts typically belong to companies/platforms themselves
// and appear in social links on platform pages (e.g., slideshare_official on Instagram).
func isOfficialPlatformAccount(urlStr string) bool {
	username := extractSocialUsername(urlStr)
	if username == "" {
		return false
	}

	// Check for official account patterns
	officialSuffixes := []string{"_official", "_app", "_hq", "_inc", "_corp"}
	for _, suffix := range officialSuffixes {
		if strings.HasSuffix(username, suffix) {
			return true
		}
	}

	// Known platform official accounts
	officialAccounts := map[string]bool{
		"slideshare": true, "slideshare_official": true,
		"linkedin": true, "linkedin_official": true,
		"instagram": true, "twitter": true, "tiktok": true,
		"facebook": true, "youtube": true, "github": true,
		"medium": true, "reddit": true,
	}

	return officialAccounts[username]
}

// extractSocialUsername extracts the username from common social media URLs.
func extractSocialUsername(urlStr string) string {
	lower := strings.ToLower(urlStr)
	patterns := []string{
		"instagram.com/", "twitter.com/", "x.com/",
		"tiktok.com/@", "facebook.com/", "youtube.com/@",
	}
	for _, prefix := range patterns {
		idx := strings.Index(lower, prefix)
		if idx < 0 {
			continue
		}
		rest := lower[idx+len(prefix):]
		// Extract until delimiter
		for i, c := range rest {
			if c == '/' || c == '?' || c == '#' {
				return rest[:i]
			}
		}
		return rest
	}
	return ""
}

// isSocialPlatform returns true if the URL matches a known social media platform.
func isSocialPlatform(url string) bool {
	return linkedin.Match(url) ||
		twitter.Match(url) ||
		linktree.Match(url) ||
		github.Match(url) ||
		gitlab.Match(url) ||
		codeberg.Match(url) ||
		google.Match(url) ||
		gravatar.Match(url) ||
		mailru.Match(url) ||
		medium.Match(url) ||
		microblog.Match(url) ||
		reddit.Match(url) ||
		replit.Match(url) ||
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
		telegram.Match(url) ||
		tryhackme.Match(url) ||
		vkontakte.Match(url) ||
		keybase.Match(url) ||
		crates.Match(url) ||
		dockerhub.Match(url) ||
		mastodon.Match(url) ||
		hackerone.Match(url) ||
		bugcrowd.Match(url) ||
		holopin.Match(url)
}

// isSameDomainContactPage returns true if link is a contact/about page on same domain.
func isSameDomainContactPage(link, base string) bool {
	host := func(u string) string {
		u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
		u = strings.TrimPrefix(u, "www.")
		if i := strings.Index(u, "/"); i >= 0 {
			u = u[:i]
		}
		return strings.ToLower(u)
	}
	if host(link) != host(base) {
		return false
	}
	lower := strings.ToLower(link)
	for _, p := range []string{"/about", "/contact", "/links", "/connect", "/socials"} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// normalizeURL normalizes a URL for deduplication.
func normalizeURL(url string) string {
	url = strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	url = strings.TrimPrefix(url, "www.")
	return strings.ToLower(strings.TrimSuffix(url, "/"))
}

// isBadRedirect returns true if the redirect should be ignored (e.g., VK badbrowser).
func isBadRedirect(resolved string) bool {
	return strings.Contains(resolved, "vk.com/badbrowser")
}

// handleRedirectWithUsernamePreservation resolves redirects while preserving usernames
// that would otherwise be lost (e.g., SlideShare URLs that redirect to /slideshow/).
// Returns a profile if username was preserved (caller should skip fetch), otherwise returns resolved URL.
func handleRedirectWithUsernamePreservation(
	ctx context.Context, url string, cache httpcache.Cacher, logger *slog.Logger,
) (preserved *profile.Profile, resolved string) {
	// Extract SlideShare username before redirect might lose it
	slideshareUsername := ""
	if slideshare.Match(url) {
		slideshareUsername = slideshare.ExtractUsername(url)
	}

	// Skip redirect resolution for known platforms (except SlideShare which redirects)
	// This avoids an HTTP request for platforms like github.com that don't redirect
	if slideshareUsername == "" && PlatformForURL(url) != "generic" {
		return nil, url
	}

	// Resolve redirects (but skip bad redirects like VK badbrowser)
	resolved = httpcache.ResolveRedirects(ctx, cache, url, logger)
	if resolved == url || isBadRedirect(resolved) {
		return nil, url
	}

	logger.InfoContext(ctx, "resolved redirect", "from", url, "to", resolved)

	// If SlideShare URL redirected to non-profile path (e.g., /slideshow/), create minimal profile
	if slideshareUsername != "" && !slideshare.Match(resolved) {
		logger.InfoContext(ctx, "slideshare redirect lost username, preserving",
			"original", url, "username", slideshareUsername, "resolved", resolved)
		return &profile.Profile{
			Platform: "slideshare",
			URL:      url,
			Username: slideshareUsername,
		}, resolved
	}

	return nil, resolved
}

// dedupeLinks removes duplicates from links, considering visited URLs.
func dedupeLinks(links []string, visited map[string]bool) []string {
	seen := make(map[string]bool, len(visited))
	for k := range visited {
		seen[k] = true
	}
	var out []string
	for _, link := range links {
		norm := normalizeURL(link)
		if !seen[norm] {
			seen[norm] = true
			out = append(out, link)
		}
	}
	return out
}

// isLikelySocialURL checks if a field value looks like a social URL.
func isLikelySocialURL(key, value string) bool {
	if !strings.HasPrefix(value, "http") {
		return false
	}
	lower := strings.ToLower(key)
	for _, k := range []string{"twitter", "linkedin", "github", "instagram", "youtube", "tiktok", "mastodon", "bluesky", "website"} {
		if strings.Contains(lower, k) {
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

// PlatformForURL returns the platform name for a URL, or "website" if unknown.
// This uses the platform registry for matching.
func PlatformForURL(url string) string {
	if p := profile.MatchURL(url); p != nil {
		return p.Name()
	}
	return "website"
}

// platformMatches checks if a URL matches the given platform name.
func platformMatches(url, platformName string) bool {
	if p := profile.LookupPlatform(platformName); p != nil {
		return p.Match(url)
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
		Logger:                   cfg.logger,
		Fetcher:                  fetcher,
		PlatformDetector:         PlatformForURL,
		MaxCandidatesPerPlatform: cfg.maxCandidatesPerPlatform,
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
		Logger:                   cfg.logger,
		Fetcher:                  fetcher,
		PlatformDetector:         PlatformForURL,
		MaxCandidatesPerPlatform: cfg.maxCandidatesPerPlatform,
	}

	guessed := guess.Related(ctx, []*profile.Profile{seedProfile}, guessCfg)

	return guessed, nil
}

// FetchEmailRecursive fetches profiles from email-based services and recursively follows links.
func FetchEmailRecursive(ctx context.Context, emails []string, opts ...Option) ([]*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	seeds, err := FetchEmail(ctx, emails, opts...)
	if err != nil {
		return nil, err
	}
	if len(seeds) == 0 {
		return nil, nil
	}

	visited := make(map[string]bool)
	var out []*profile.Profile
	for _, p := range seeds {
		if norm := normalizeURL(p.URL); !visited[norm] {
			visited[norm] = true
			out = append(out, p)
		}
	}

	type item struct {
		url   string
		depth int
	}
	const maxDepth, maxLinks = 3, 8

	var queue []item
	for _, p := range seeds {
		for _, link := range p.SocialLinks {
			if !visited[normalizeURL(link)] && isValidProfileURL(link) {
				queue = append(queue, item{link, 1})
			}
		}
		if p.Website != "" && !visited[normalizeURL(p.Website)] && isValidProfileURL(p.Website) {
			queue = append(queue, item{p.Website, 1})
		}
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		// Handle redirects, preserving usernames that might be lost
		p, resolved := handleRedirectWithUsernamePreservation(ctx, cur.url, cfg.cache, cfg.logger)
		if p != nil {
			out = append(out, p)
			continue
		}
		cur.url = resolved

		norm := normalizeURL(cur.url)
		if visited[norm] {
			continue
		}
		visited[norm] = true

		cfg.logger.InfoContext(ctx, "fetching profile", "url", cur.url, "depth", cur.depth, "visited", len(visited))

		p, err = Fetch(ctx, cur.url, opts...)
		if err != nil {
			cfg.logger.WarnContext(ctx, "failed to fetch profile", "url", cur.url, "error", err)
			continue
		}
		out = append(out, p)

		if cur.depth >= maxDepth {
			continue
		}

		onlyKnown := p.Platform == "website"
		var links []string
		for _, link := range p.SocialLinks {
			if !visited[normalizeURL(link)] && isValidProfileURL(link) {
				if !onlyKnown || isSocialPlatform(link) || isSameDomainContactPage(link, cur.url) {
					links = append(links, link)
				}
			}
		}
		if p.Website != "" && !visited[normalizeURL(p.Website)] && isValidProfileURL(p.Website) {
			links = append(links, p.Website)
		}

		keys := make([]string, 0, len(p.Fields))
		for k := range p.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if v := p.Fields[k]; isLikelySocialURL(k, v) && !visited[normalizeURL(v)] && isValidProfileURL(v) {
				links = append(links, v)
			}
		}

		if len(links) > maxLinks {
			links = links[:maxLinks]
		}
		for _, link := range dedupeLinks(links, visited) {
			queue = append(queue, item{link, cur.depth + 1})
		}
	}

	return out, nil
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

func fetchPyPI(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []pypi.Option
	if cfg.cache != nil {
		opts = append(opts, pypi.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, pypi.WithLogger(cfg.logger))
	}

	client, err := pypi.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchScratch(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []scratch.Option
	if cfg.cache != nil {
		opts = append(opts, scratch.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, scratch.WithLogger(cfg.logger))
	}

	client, err := scratch.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchSlashdot(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []slashdot.Option
	if cfg.cache != nil {
		opts = append(opts, slashdot.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, slashdot.WithLogger(cfg.logger))
	}

	client, err := slashdot.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchTumblr(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []tumblr.Option
	if cfg.cache != nil {
		opts = append(opts, tumblr.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, tumblr.WithLogger(cfg.logger))
	}

	client, err := tumblr.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchObservableHQ(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []observablehq.Option
	if cfg.cache != nil {
		opts = append(opts, observablehq.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, observablehq.WithLogger(cfg.logger))
	}

	client, err := observablehq.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchBlogger(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []blogger.Option
	if cfg.cache != nil {
		opts = append(opts, blogger.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, blogger.WithLogger(cfg.logger))
	}

	client, err := blogger.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchBoardGameGeek(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []boardgamegeek.Option
	if cfg.cache != nil {
		opts = append(opts, boardgamegeek.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, boardgamegeek.WithLogger(cfg.logger))
	}

	client, err := boardgamegeek.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchDuolingo(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []duolingo.Option
	if cfg.cache != nil {
		opts = append(opts, duolingo.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, duolingo.WithLogger(cfg.logger))
	}

	client, err := duolingo.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHackerRank(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []hackerrank.Option
	if cfg.cache != nil {
		opts = append(opts, hackerrank.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, hackerrank.WithLogger(cfg.logger))
	}

	client, err := hackerrank.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchTradingView(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []tradingview.Option
	if cfg.cache != nil {
		opts = append(opts, tradingview.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, tradingview.WithLogger(cfg.logger))
	}

	client, err := tradingview.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}
